const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      required: true,
      trim: true,
    },
    lastName: {
      type: String,
      required: true,
      trim: true,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      trim: true,
      lowercase: true,
    },
    password: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      unique: true,
      sparse: true, // ✅ Allows multiple null values until username is set
      lowercase: true,
      trim: true,
    },
    category: {
      type: String,
      required: false, // ✅ Category is optional initially
      trim: true,
    }
  },
  {
    timestamps: true,
  }
);

// Virtual field for fullName
userSchema.virtual("fullName").get(function () {
  return `${this.firstName} ${this.lastName}`;
});

userSchema.set("toJSON", { virtuals: true });
userSchema.set("toObject", { virtuals: true });

const User = mongoose.model("User", userSchema);
module.exports = User;
