require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const device = require("express-device");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("./models/User"); 
const cloudinary = require("./cloudinary");
const multer = require("multer");
const useragent = require("useragent"); 
const uaParser = require("ua-parser-js");
const path = require("path");
const app = express();
app.use(device.capture()); 
app.use(cors());
app.use(express.json());

const JWT_SECRET = "your_secret_key"; 

const storage = multer.memoryStorage(); 
const upload = multer({ storage });

mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

const getDeviceType = (device) => {
  if (!device || !device.type) return "Others"; 

  switch (device.type) {
    case "desktop":
      return "Windows"; 
    case "tablet":
      return "Tablet";
    case "phone":
      return "Mobile"; 
    default:
      return "Others";
  }
};

app.post("/api/track-login", async (req, res) => {
  try {
    console.log("📢 Device Info:", req.device); 

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

    const deviceType = getDeviceType(req.device);

    if (!user.traffic || Array.isArray(user.traffic)) {
      console.warn(`⚠️ Fixing traffic field for user: ${username}`);
      await User.updateOne(
        { _id: user._id },
        { $set: { traffic: { Windows: 0, Mac: 0, Linux: 0, iOS: 0, Android: 0, Tablet: 0, Mobile: 0, Others: 0 } } }
      );
      user = await User.findOne({ username }); 
    }

    if (!user.traffic[deviceType]) {
      await User.updateOne(
        { _id: user._id },
        { $set: { [`traffic.${deviceType}`]: 0 } }
      );
    }

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

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ firstName, lastName, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ success: true, message: "User registered successfully", userId: newUser._id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ success: false, message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: "1h" });

    res.json({ success: true, token, userId: user._id, username: user.username });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

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
    const token = req.headers.authorization?.split(" ")[1]; 
    if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });

    const decoded = jwt.verify(token, JWT_SECRET); 
    const user = await User.findById(decoded.userId).select("firstName lastName email");

    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]; 
  if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid token" });
    req.userId = decoded.userId; 
    next();
  });
};

app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password"); 
    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

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
      _id: new mongoose.Types.ObjectId(), 
      clicks: 0, 
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
      entry: newEntry 
    });

  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

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
    const { title, url, tag, icon } = req.body; 
    const token = req.headers.authorization.split(" ")[1];

    const decoded = jwt.verify(token, "your_secret_key");
    const user = await User.findById(decoded.userId);

    if (!user) return res.status(404).json({ success: false, message: "User not found" });

    let updated = false;

    user.addLinks = user.addLinks.map(link =>
      link._id.toString() === id ? { ...link, title, url, tag, icon } : link
    );

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

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

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

    const user = await User.findOneAndUpdate(
      { _id: req.userId, [`${updateField}._id`]: linkId },
      { $inc: { [`${updateField}.$.clicks`]: 1 } }, 
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

    const user = await User.findById(req.userId).select("addLinks");
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.addLinks || user.addLinks.length === 0) {
      return res.json({ success: true, links: [] }); 
    }

    const links = user.addLinks.map((link) => ({
      url: link.url,
      title: link.title || "Untitled",
      icon: link.icon || "default-icon.png", 
    }));

    res.json({ success: true, links });
  } catch (error) {
    console.error("Error fetching user links:", error);
    res.status(500).json({ success: false, message: "Server Error", error: error.message });
  }
});

app.get("/api/user-links-shop", authenticateToken, async (req, res) => {
  try {

    const user = await User.findById(req.userId).select("addShop"); 
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (!user.addShop || user.addShop.length === 0) {
      return res.json({ success: true, shopLinks: [] }); 
    }

    const shopLinks = user.addShop.map((link) => ({
      url: link.url,
      title: link.title || "Untitled",
      icon: link.icon || "default-icon.png",
    }));

    res.json({ success: true, shopLinks }); 
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

app.post("/api/upload-profile-image", authenticateToken, upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: "No file uploaded" });

    const imageBase64 = req.file.buffer.toString("base64"); 

    const updatedUser = await User.findByIdAndUpdate(
      req.userId,
      { image: `data:${req.file.mimetype};base64,${imageBase64}` }, 
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
  const token = req.headers.authorization?.split(" ")[1]; 
  if (!token) return res.status(401).json({ success: false, message: "Unauthorized" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ success: false, message: "Invalid token" });
    req.user = { userId: decoded.userId }; 
    next();
  });
};

app.post("/api/save-appearance", auth, async (req, res) => {
  const { settings } = req.body;

  if (!settings) {
    return res.status(400).json({ message: "Settings are required." });
  }

  try {
    const user = await User.findById(req.user.userId); 
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    user.settings = { ...user.settings, ...settings };
    await user.save();

    res.json({ message: "Settings saved successfully." });
  } catch (err) {
    console.error("Error saving settings:", err); 
    res.status(400).json({ message: "Error saving settings.", error: err.message });
  }
});

app.get("/api/get-appearance", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ message: "User not found." });
    }

    res.json({ settings: user.settings });
  } catch (err) {
    console.error("Error fetching settings:", err); 
    res.status(400).json({ message: "Error fetching settings.", error: err.message });
  }
});

app.get("/api/public/user-data/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId).lean();
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    console.log("User Data:", user);

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

    const today = new Date().toISOString().split("T")[0]; 
    const currentMonth = today.slice(0, 7); 

    const updateFields = {};

    if (!linkId || linkId === "button_click") {
      if (type === "shop") {
        updateFields.totalshopclicks = 1;
      } else if (type === "link") {
        updateFields.totallinkclicks = 1;
      }

      updateFields[`totaldatewiseclicks.${today}`] = 1; 
      updateFields[`monthlyClicks.${currentMonth}.${type}`] = 1; 

      await User.findByIdAndUpdate(req.userId, { $inc: updateFields }, { new: true });

      return res.json({ success: true, message: "Button click counted successfully" });
    }

    if (!mongoose.Types.ObjectId.isValid(linkId)) {
      return res.status(400).json({ success: false, message: "Invalid link ID" });
    }

    const updateField = type === "link" ? "addLinks" : "addShop";

    const user = await User.findOneAndUpdate(
      { _id: req.userId, [`${updateField}._id`]: linkId },
      {
        $inc: {
          [`${updateField}.$.clicks`]: 1,
          [`totaldatewiseclicks.${today}`]: 1,
          ...(type === "shop" ? { totalshopclicks: 1 } : { totallinkclicks: 1 }),
          [`monthlyClicks.${currentMonth}.${type}`]: 1, 
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
    const today = new Date().toISOString().split("T")[0]; 
    const currentMonth = today.slice(0, 7); 

    const updateFields = {
      cta: 1,
      [`totaldatewiseclicks.${today}`]: 1, 
      [`monthlyClicks.${currentMonth}.cta`]: 1, 
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

    const monthlyClicks = user.monthlyClicks || {};
    const monthlyData = [];

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

    const user = await User.findById(req.userId, "totallinkclicks totalshopclicks cta monthlyClicks traffic");

    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    const monthlyClicks = user.monthlyClicks || {};
    const monthlyData = Object.entries(monthlyClicks).map(([month, clicks]) => ({
      month,
      totalClicks: (clicks.link || 0) + (clicks.shop || 0) + (clicks.cta || 0),
      linkClicks: clicks.link || 0,
      shopClicks: clicks.shop || 0,
      ctaClicks: clicks.cta || 0,
    }));

    monthlyData.sort((a, b) => new Date(a.month) - new Date(b.month));

    res.json({
      success: true,
      totallinkclicks: user.totallinkclicks || 0,
      totalshopclicks: user.totalshopclicks || 0,
      cta: user.cta || 0,
      monthlyClicks: monthlyData,
      traffic: user.traffic || {}, 
    });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.get("/traffic", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId); 
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

    const latestLinks = [...user.addLinks]
      .sort((a, b) => b.clicks - a.clicks) 
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

    const user = await User.findById(req.userId);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found" });
    }

    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ success: false, message: "Email already in use" });
      }
      user.email = email;
    }

    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;

    let passwordChanged = false;
    if (password && confirmPassword) {
      if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: "Passwords do not match" });
      }
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
      passwordChanged = true;
    }

    await user.save();

    if (passwordChanged) {
      return res.status(200).json({ success: true, passwordChanged: true, message: "Password updated, please login again." });
    }

    res.status(200).json({ success: true, message: "Profile updated successfully!" });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));