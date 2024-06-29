const mongoose = require('mongoose');
mongoose.connect('mongodb://127.0.0.1:27017/OTP-verify');

mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});



const plm = require("passport-local-mongoose");

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, 'Username is required'],
  },
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [6, 'Password must be at least 6 characters'],
    maxlength: [20, 'Password must be at most 20 characters'],
    validate: {
      validator: function (v) {
        return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,20}$/.test(v);
      },
      message: 'Password requirements: uppercase, lowercase, number, special character.',
    },
  },
  isVerified: {
    type: Boolean,
    default: false,
  },
  otp: {
    type: String,
    minlength: [6, 'OTP must be exactly 6 characters'],
    maxlength: [6, 'OTP must be exactly 6 characters'],
  },
  otpExpires: {
    type: Date, // Corrected typo
  },
  posts: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'posts'
  }],
  image: {
       type: String,
       default: 'https://cdn-icons-png.flaticon.com/512/3135/3135715.png',
       required: [true, 'Image is required'],
  },
  files: {
    type: [String],
    default: [],
    required: [true, 'Files are required'],
  }
});




userSchema.plugin(plm);

module.exports = mongoose.model('users', userSchema);
