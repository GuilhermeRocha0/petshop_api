const mongoose = require('mongoose')

const User = mongoose.model('User', {
  name: String,
  cpf: String,
  email: String,
  password: String,
  role: String
})

module.exports = User
