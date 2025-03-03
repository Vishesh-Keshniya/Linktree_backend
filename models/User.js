const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, required: true },
    username: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
    profileTitle: { type: String, trim: true },
    bio: { type: String, trim: true },

    image: { type: String, default: "./uploads/ava.png" },

    settings: {
      layout: { type: String, default: "stack" },
      shadowStyle: { type: String, default: "soft" },
      borderStyle: { type: String, default: "rounded" },
      buttonStyle: { type: String, default: "solid" },
      linkBgColor: { type: String, default: "#D9D9D9" },
      linkFontColor: { type: String, default: "#F5F5F3" },
      phoneFontColor: { type: String, default: "#000000" },
      selectedFont: { type: String, default: "DM Sans" },
      selectedTheme: { type: String, default: "" },
      selectedLiTheme: { type: String, default: "" },
      phoneHeaderColor: { type: String, default: "#000000" },
    },

    linkTree: {
      type: String,
      unique: true,
      sparse: true,
      default: function () {
        return new mongoose.Types.ObjectId().toString();
      },
    },

    addLinks: [
      {
        title: String,
        url: String,
        tag: String,
        clicks: { type: Number, default: 0 },
        icon: String,
      },
    ],
    addShop: [
      {
        title: String,
        url: String,
        tag: String,
        clicks: { type: Number, default: 0 },
        icon: String,
      },
    ],
    totalshopclicks: { type: Number, default: 0 },
    totallinkclicks: { type: Number, default: 0 },
    cta: { type: Number, default: 0 },

    totaldatewiseclicks: { type: Object, default: {} },

    monthlyClicks: {
      type: Object,
      default: {},
    },

    traffic: {
      Linux: { type: Number, default: 0 },
      Mac: { type: Number, default: 0 },
      iOS: { type: Number, default: 0 },
      Windows: { type: Number, default: 0 },
      Android: { type: Number, default: 0 },
      Others: { type: Number, default: 0 },
    },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
module.exports = User;
