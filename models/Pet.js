const mongoose = require('mongoose')

const Pet = mongoose.model('Pet', {
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  name: { type: String, required: true },
  size: { type: String, enum: ['pequeno', 'médio', 'grande'], required: true },
  age: { type: Number, required: true },
  breed: { type: String, required: true },
  notes: { type: String }
})

module.exports = Pet
