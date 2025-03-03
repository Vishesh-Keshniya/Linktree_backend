const cloudinary = require("cloudinary").v2;
require("dotenv").config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,  // ✅ Ensure it matches Cloudinary Console
  api_key: process.env.CLOUDINARY_API_KEY,  // ✅ Use the correct API key
  api_secret: process.env.CLOUDINARY_API_SECRET,  // ✅ Use the correct API secret
});

module.exports = cloudinary;
