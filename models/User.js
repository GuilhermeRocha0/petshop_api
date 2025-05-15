const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
  name: String,
  cpf: String,
  email: String,
  password: String,
  role: {
    type: String,
    enum: ['ADMIN', 'CUSTOMER'],
    default: 'CUSTOMER'
  }
})

const User = mongoose.model('User', UserSchema)

module.exports = User
