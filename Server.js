require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const device = require("express-device");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/User"); // Import User model
const cloudinary = require("./cloudinary");
const multer = require("multer");
const useragent = require("useragent"); // Import useragent package
const uaParser = require("ua-parser-js");
const path = require("path");
const app = express();
app.use(device.capture()); // ✅ Must be placed BEFORE routes
app.use(cors());
app.use(express.json());

const JWT_SECRET = "your_secret_key"; // Use a secure secret key

const storage = multer.memoryStorage(); // Stores image in memory
const upload = multer({ storage });

// 🔹 Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// 🔹 User Registration Route (Without Username)

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

app.use(express.static(path.join(__dirname, "dist"), {
  setHeaders: (res, path) => {
    if (path.endsWith(".js")) {
      res.setHeader("Content-Type", "application/javascript");
    }
  }
}));

// Handle React Routes (SPA)
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "dist", "index.html"));
});

const getDeviceType = (device) => {
  if (!device || !device.type) return "Others"; // Ensure device exists

  switch (device.type) {
    case "desktop":
      return "Windows"; // Assume desktop means Windows
    case "tablet":
      return "Tablet";
    case "phone":
      return "Mobile"; // Generic mobile category
    default:
      return "Others";
  }
};








// API to track login and update device count
app.post("/api/track-login", async (req, res) => {
  try {
    console.log("📢 Device Info:", req.device); // Debugging

    const { username } = req.body;
    if (!username) {
      console.error("❌ Error: Username not provided");
      return res.status(400).json({ success: false, message: "Username is required" });
    }

    let user = await User.findOne({ username });
    if (!user) {
      console.error(`❌ Error: User '${username}' not found`);
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Get the device type
    const deviceType = getDeviceType(req.device);

    // Step 1: Fix `traffic` if it's an array or missing
    if (!user.traffic || Array.isArray(user.traffic)) {
      console.warn(`⚠️ Fixing traffic field for user: ${username}`);
      await User.updateOne(
        { _id: user._id },
        { $set: { traffic: { Windows: 0, Mac: 0, Linux: 0, iOS: 0, Android: 0, Tablet: 0, Mobile: 0, Others: 0 } } }
      );
      user = await User.findOne({ username }); // Refresh user data
    }

    // Step 2: Ensure deviceType exists before incrementing
    if (!user.traffic[deviceType]) {
      await User.updateOne(
        { _id: user._id },
        { $set: { [`traffic.${deviceType}`]: 0 } }
      );
    }

    // Step 3: Increment the device count
    await User.updateOne(
      { _id: user._id },
      { $inc: { [`traffic.${deviceType}`]: 1 } }
    );

    console.log(`✅ Device '${deviceType}' count updated for '${username}'`);
    res.json({ success: true, message: `Device tracked: ${deviceType}` });
  } catch (error) {
    console.error("❌ Internal Server Error:", error);
    res.status(500).json({ success: false, message: "Internal server error", error: error.message });
  }
});

app.post("/api/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password } = req.body;

    // Check if email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, message: "Email already exists" });

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create User (without username)
    const newUser = new User({ firstName, lastName, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ success: true, message: "User registered successfully", userId: newUser._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// 🔹 User Login Route
app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if user exists by username
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ success: false, message: "User not found" });

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ success: true, token, userId: user._id, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});


// 🔹 Set Username Route (After Login)
app.post("/api/update-details", async (req, res) => {
  try {
    const { userId, username, category } = req.body;

    if (!userId || !username || !category) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { username, category },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({ success: true, message: "Details updated successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

app.get("/api/user-details", async (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1]; // Get token from headers
    if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });

    const decoded = jwt.verify(token, JWT_SECRET); // Decode JWT
    const user = await User.findById(decoded.userId).select("firstName lastName email");

    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});






const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Get token from headers
  if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid token" });
    req.userId = decoded.userId; // Attach userId to the request object
    next();
  });
};







app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password"); // Exclude password from response
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});





// 🔹 Add Link or Shop Entry
app.post("/api/add-entry", authenticateToken, async (req, res) => {
  try {
    const { title, url, type, tag } = req.body;
    if (!title || !url) {
      return res.status(400).json({ success: false, message: "Title and URL are required" });
    }

    const iconMap = {
      Instagram: "instr.png",
      Facebook: "fb.png",
      YouTube: "ytr.png",
      X: "x.png",
      Swiggi: "swiggi.png",
      Flipkart: "flipkart.png",
      Zomato: "zomato.png",
      Other: "shop.png",
    };

    const newEntry = {
      title,
      url,
      tag,
      icon: iconMap[tag] || "default.png",
      _id: new mongoose.Types.ObjectId(), // ✅ Ensure a unique ID is generated
      clicks: 0, // ✅ Initialize clicks count
    };

    const updateField = type === "link" ? "addLinks" : "addShop";
    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { $push: { [updateField]: newEntry } },
      { new: true }
    );

    res.status(201).json({ 
      success: true, 
      message: "Entry added successfully", 
      entry: newEntry // ✅ Send back the new entry with its ID
    });

  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});




// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ success: false, message: "Access Denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(400).json({ success: false, message: "Invalid Token" });
  }
};

// ✅ **Update Link (PUT)**
app.put("/api/update-link/:id", verifyToken, async (req, res) => {
  const { tag, url } = req.body;
  const linkId = req.params.id;

  if (!mongoose.Types.ObjectId.isValid(linkId)) {
    return res.status(400).json({ success: false, message: "Invalid link ID" });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    let updated = false;

    // 🔥 Search inside addLinks array
    user.addLinks.forEach((link) => {
      if (link._id.toString() === linkId) {
        link.tag = tag;
        link.url = url;
        updated = true;
      }
    });

    if (!updated) {
      return res.status(404).json({ success: false, message: "Link not found" });
    }

    await user.save();
    res.json({ success: true, message: "Link updated successfully" });

  } catch (error) {
    console.error("Error updating link:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// ✅ **Delete Link (DELETE)**
app.delete("/api/delete-link/:id", verifyToken, async (req, res) => {
  const linkId = req.params.id;

  if (!mongoose.Types.ObjectId.isValid(linkId)) {
    return res.status(400).json({ success: false, message: "Invalid link ID" });
  }

  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    user.addLinks = user.addLinks.filter((link) => link._id.toString() !== linkId);
    await user.save();

    res.json({ success: true, message: "Link deleted successfully" });

  } catch (error) {
    console.error("Error deleting link:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});


app.put("/api/edit-entry/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { title, url, tag, icon } = req.body; // Include icon
    const token = req.headers.authorization.split(" ")[1];

    // Verify user from token
    const decoded = jwt.verify(token, "your_secret_key");
    const user = await User.findById(decoded.userId);

    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    let updated = false;

    // Update addLinks array
    user.addLinks = user.addLinks.map(link =>
      link._id.toString() === id ? { ...link, title, url, tag, icon } : link
    );

    // Update addShop array
    user.addShop = user.addShop.map(shop =>
      shop._id.toString() === id ? { ...shop, title, url, tag, icon } : shop
    );

    await user.save();
    res.json({ success: true, message: "Entry updated successfully" });
  } catch (error) {
    console.error("Error updating entry:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// DELETE endpoint to delete a link by ID
// ✅ **Delete Link (DELETE)**
app.delete("/api/entries/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    let { type } = req.query;

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ success: false, message: "Invalid entry ID" });
    }

    if (!type || !["link", "shop"].includes(type)) {
      return res.status(400).json({ success: false, message: "Invalid or missing entry type" });
    }

    const updateField = type === "link" ? "addLinks" : "addShop";

    // ✅ Check if user exists first
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // ✅ Use `$pull` to remove entry from correct array
    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { $pull: { [updateField]: { _id: id } } },
      { new: true }
    );

    if (!updatedUser) {
      return res.status(404).json({ success: false, message: "Entry not found" });
    }

    res.json({ success: true, message: `${type === "link" ? "Link" : "Shop"} deleted successfully` });

  } catch (error) {
    console.error("Error deleting entry:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});


app.post("/api/increment-clicks", authenticateToken, async (req, res) => {
  try {
    const { linkId, type } = req.body;

    if (!linkId || !type) {
      return res.status(400).json({ success: false, message: "Invalid data" });
    }

    if (!mongoose.Types.ObjectId.isValid(linkId)) {
      return res.status(400).json({ success: false, message: "Invalid link ID" });
    }

    const updateField = type === "link" ? "addLinks" : "addShop";

    // ✅ Find the user and update the clicks for the specific link
    const user = await User.findOneAndUpdate(
      { _id: req.userId, [`${updateField}._id`]: linkId },
      { $inc: { [`${updateField}.$.clicks`]: 1 } }, // ✅ Increment clicks
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: "User or Link not found" });
    }

    res.json({ success: true, message: "Click counted successfully" });
  } catch (error) {
    console.error("Error updating clicks:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

app.get("/api/user-links", authenticateToken, async (req, res) => {
  try {
    // 🔹 Ensure user exists
    const user = await User.findById(req.userId).select("addLinks");
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.addLinks || user.addLinks.length === 0) {
      return res.json({ success: true, links: [] }); // Return empty array instead of error
    }

    // Map through the links and include the icon field
    const links = user.addLinks.map((link) => ({
      url: link.url,
      title: link.title || "Untitled",
      icon: link.icon || "default-icon.png", // Use a default icon if none is provided
    }));

    res.json({ success: true, links });
  } catch (error) {
    console.error("Error fetching user links:", error);
    res.status(500).json({ success: false, message: "Server Error", error: error.message });
  }
});


app.get("/api/user-links-shop", authenticateToken, async (req, res) => {
  try {
    // 🔹 Ensure user exists
    const user = await User.findById(req.userId).select("addShop"); // Select addShop instead of addLinks
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.addShop || user.addShop.length === 0) {
      return res.json({ success: true, shopLinks: [] }); // Fix response key
    }

    // Map through the shop links and include the icon field
    const shopLinks = user.addShop.map((link) => ({
      url: link.url,
      title: link.title || "Untitled",
      icon: link.icon || "default-icon.png",
    }));

    res.json({ success: true, shopLinks }); // Fix response key
  } catch (error) {
    console.error("Error fetching shop links:", error);
    res.status(500).json({ success: false, message: "Server Error", error: error.message });
  }
});


app.put("/api/update-profile-image", authenticateToken, async (req, res) => {
  try {
    const { image } = req.body;
    if (!image) return res.status(400).json({ success: false, message: "No image provided" });

    const updatedUser = await User.findByIdAndUpdate(req.userId, { image }, { new: true });

    if (!updatedUser) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, message: "Profile image updated", image: updatedUser.image });
  } catch (error) {
    console.error("Error updating profile image:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});



// 🔹 Upload Profile Image API (Save Image in MongoDB)
app.post("/api/upload-profile-image", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });

    const imageBase64 = req.file.buffer.toString("base64"); // Convert image to Base64

    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { image: `data:${req.file.mimetype};base64,${imageBase64}` }, // Store Base64 image
      { new: true }
    );

    if (!updatedUser) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, message: "Profile image updated", image: updatedUser.image });
  } catch (error) {
    console.error("Error uploading image:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});


app.post("/api/remove-profile-image", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // ✅ Set image field to default
    user.image = "ava.png";
    await user.save();

    res.json({ success: true, message: "Profile image removed successfully" });
  } catch (error) {
    console.error("Error removing profile image:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});





app.post("/api/update-settings", authenticateToken, async (req, res) => {
  try {
    console.log("Received request to update settings:", req.body);

    const { phoneHeaderColor, bio } = req.body;

    if (!req.userId) {
      return res.status(401).json({ success: false, message: "Unauthorized request" });
    }

    // Fetch user before updating for debugging
    const userBefore = await User.findById(req.userId);
    console.log("Before Update:", userBefore);

    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      {
        "settings.phoneHeaderColor": phoneHeaderColor,
        bio: bio,
      },
      { new: true, runValidators: true }
    );

    if (!updatedUser) {
      console.log("User not found");
      return res.status(404).json({ success: false, message: "User not found" });
    }

    console.log("Updated settings:", updatedUser.settings);
    res.json({
      success: true,
      message: "Settings updated successfully",
      settings: updatedUser.settings,
      bio: updatedUser.bio,
    });
  } catch (error) {
    console.error("Error updating settings:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});


const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; // Get token from headers
  if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid token" });
    req.user = { userId: decoded.userId }; // Attach userId to req.user
    next();
  });
};

app.post("/api/save-appearance", auth, async (req, res) => {
  const { settings } = req.body;

  // Validate the request body
  if (!settings) {
    return res.status(400).json({ message: "Settings are required." });
  }

  try {
    const user = await User.findById(req.user.userId); // Use req.user.userId
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Update user settings
    user.settings = { ...user.settings, ...settings };
    await user.save();

    res.json({ message: "Settings saved successfully." });
  } catch (err) {
    console.error("Error saving settings:", err); // Log the error details
    res.status(400).json({ message: "Error saving settings.", error: err.message });
  }
});
// Appearance settings update






app.get("/api/get-appearance", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    // Return the user's settings
    res.json({ settings: user.settings });
  } catch (err) {
    console.error("Error fetching settings:", err); // Log the error details
    res.status(400).json({ message: "Error fetching settings.", error: err.message });
  }
});


app.get("/api/public/user-data/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    // Find the user in the database
    const user = await User.findById(userId).lean();
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Log the user data being sent
    console.log("User Data:", user);

    // Return only necessary public details
    res.json({
      success: true,
      user: {
        username: user.username,
        image: user.image || "/uploads/ava.png",
        bio: user.bio,
        settings: user.settings,
      },
      links: user.addLinks || [],
      shopLinks: user.addShop || [],
    });
  } catch (error) {
    console.error("Error fetching user data:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});



















app.post("/api/increment-clickss", authenticateToken, async (req, res) => {
  try {
    let { linkId, type } = req.body;

    console.log("Received Click Data:", { linkId, type });

    if (!type) {
      return res.status(400).json({ success: false, message: "Type is required" });
    }

    const today = new Date().toISOString().split("T")[0]; // Get today's date in "YYYY-MM-DD" format
    const currentMonth = today.slice(0, 7); // Get current month in "YYYY-MM" format

    const updateFields = {};

    // If it's a button click (e.g., navigating between Links and Shop), update totals
    if (!linkId || linkId === "button_click") {
      if (type === "shop") {
        updateFields.totalshopclicks = 1;
      } else if (type === "link") {
        updateFields.totallinkclicks = 1;
      }

      updateFields[`totaldatewiseclicks.${today}`] = 1; // Increment today's click count
      updateFields[`monthlyClicks.${currentMonth}.${type}`] = 1; // Increment monthly click count for this type

      await User.findByIdAndUpdate(req.userId, { $inc: updateFields }, { new: true });

      return res.json({ success: true, message: "Button click counted successfully" });
    }

    // Validate linkId for actual link clicks
    if (!mongoose.Types.ObjectId.isValid(linkId)) {
      return res.status(400).json({ success: false, message: "Invalid link ID" });
    }

    const updateField = type === "link" ? "addLinks" : "addShop";

    // Update clicks for the specific link or shop item
    const user = await User.findOneAndUpdate(
      { _id: req.userId, [`${updateField}._id`]: linkId },
      {
        $inc: {
          [`${updateField}.$.clicks`]: 1,
          [`totaldatewiseclicks.${today}`]: 1,
          ...(type === "shop" ? { totalshopclicks: 1 } : { totallinkclicks: 1 }),
          [`monthlyClicks.${currentMonth}.${type}`]: 1, // Increment monthly clicks for link/shop
        },
      },
      { new: true }
    );

    if (!user) {
      return res.status(404).json({ success: false, message: "User or Link not found" });
    }

    res.json({ success: true, message: "Link click counted successfully" });
  } catch (error) {
    console.error("Error updating clicks:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});


app.post("/api/increment-cta-click", authenticateToken, async (req, res) => {
  try {
    const today = new Date().toISOString().split("T")[0]; // Get today's date in "YYYY-MM-DD"
    const currentMonth = today.slice(0, 7); // Get current month in "YYYY-MM"

    const updateFields = {
      cta: 1,
      [`totaldatewiseclicks.${today}`]: 1, // Increment today's click count
      [`monthlyClicks.${currentMonth}.cta`]: 1, // Increment monthly CTA click count
    };

    const user = await User.findByIdAndUpdate(req.userId, { $inc: updateFields }, { new: true });

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    res.json({ success: true, message: "CTA click counted successfully" });
  } catch (error) {
    console.error("Error updating CTA clicks:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});







app.get("/analytics", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId, "totallinkclicks totalshopclicks cta monthlyClicks");
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Extract the monthly clicks data from user document
    const monthlyClicks = user.monthlyClicks || {};
    const monthlyData = [];

    // Loop through each month in the monthlyClicks object
    for (const [month, clicks] of Object.entries(monthlyClicks)) {
      const totalClicks = (clicks.link || 0) + (clicks.shop || 0) + (clicks.cta || 0);
      monthlyData.push({
        month,
        totalClicks,
        linkClicks: clicks.link || 0,
        shopClicks: clicks.shop || 0,
        ctaClicks: clicks.cta || 0,
      });
    }

    // Sort the monthly data by month (optional)
    monthlyData.sort((a, b) => new Date(a.month) - new Date(b.month));

    res.json({
      success: true,
      totallinkclicks: user.totallinkclicks || 0,
      totalshopclicks: user.totalshopclicks || 0,
      cta: user.cta || 0,
      monthlyClicks: monthlyData,
    });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});




app.get("/analytics", authenticateToken, async (req, res) => {
  try {
    // Fetch user data with selected fields
    const user = await User.findById(req.userId, "totallinkclicks totalshopclicks cta monthlyClicks traffic");
    
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Extract and process monthly clicks data
    const monthlyClicks = user.monthlyClicks || {};
    const monthlyData = Object.entries(monthlyClicks).map(([month, clicks]) => ({
      month,
      totalClicks: (clicks.link || 0) + (clicks.shop || 0) + (clicks.cta || 0),
      linkClicks: clicks.link || 0,
      shopClicks: clicks.shop || 0,
      ctaClicks: clicks.cta || 0,
    }));

    // Sort data by month (optional)
    monthlyData.sort((a, b) => new Date(a.month) - new Date(b.month));

    res.json({
      success: true,
      totallinkclicks: user.totallinkclicks || 0,
      totalshopclicks: user.totalshopclicks || 0,
      cta: user.cta || 0,
      monthlyClicks: monthlyData,
      traffic: user.traffic || {}, // Include traffic data
    });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});



app.get("/traffic", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId); // Get user data from DB
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, traffic: user.traffic });
  } catch (error) {
    res.status(500).json({ success: false, message: "Server error", error });
  }
});


app.get("/site-traffic", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    let youtubeClicks = 0,
      facebookClicks = 0,
      instagramClicks = 0,
      otherClicks = 0;

    // Function to categorize clicks based on `tag`
    const categorizeClicks = (links) => {
      links.forEach((link) => {
        if (link.tag.toLowerCase() === "youtube") youtubeClicks += link.clicks;
        else if (link.tag.toLowerCase() === "facebook") facebookClicks += link.clicks;
        else if (link.tag.toLowerCase() === "instagram") instagramClicks += link.clicks;
        else otherClicks += link.clicks;
      });
    };

    categorizeClicks(user.addLinks);
    categorizeClicks(user.addShop);

    console.log("YouTube Clicks:", youtubeClicks);
    console.log("Facebook Clicks:", facebookClicks);
    console.log("Instagram Clicks:", instagramClicks);
    console.log("Other Clicks:", otherClicks);

    res.json({
      success: true,
      traffic: {
        Youtube: youtubeClicks,
        Facebook: facebookClicks,
        Instagram: instagramClicks,
        Other: otherClicks,
      },
    });
  } catch (error) {
    console.error("Error fetching site traffic:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});


app.get("/api/user-links-traffic", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    // Sort links by latest and get only the last 6
    const latestLinks = [...user.addLinks]
      .sort((a, b) => b.clicks - a.clicks) // Sort by clicks descending
      .slice(0, 6);

    res.json({ success: true, links: latestLinks });
  } catch (error) {
    console.error("Error fetching user links:", error);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});





app.put("/api/update-user", authenticateToken, async (req, res) => {
  try {
    const { firstName, lastName, email, password, confirmPassword } = req.body;

    // Ensure the user exists
    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    // Check if email is being changed
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ success: false, message: "Email already in use" });
      }
      user.email = email;
    }

    // Update name fields
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;

    // ✅ If password is changed, hash it and force logout
    let passwordChanged = false;
    if (password && confirmPassword) {
      if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: "Passwords do not match" });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      passwordChanged = true;
    }

    // Save updated user details
    await user.save();

    // If password was changed, force logout
    if (passwordChanged) {
      return res.status(200).json({ success: true, passwordChanged: true, message: "Password updated, please login again." });
    }

    res.status(200).json({ success: true, message: "Profile updated successfully!" });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
