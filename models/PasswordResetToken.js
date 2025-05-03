const mongoose = require('mongoose')

const PasswordResetToken = mongoose.model('PasswordResetToken', {
  userId: mongoose.Schema.Types.ObjectId,
  code: String,
  expiresAt: Date
})

module.exports = PasswordResetToken
