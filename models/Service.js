const mongoose = require('mongoose')

const Service = mongoose.model('Service', {
  name: { type: String, required: true },
  price: { type: Number, required: true },
  estimatedTime: { type: Number, required: true } // tempo em minutos
})

module.exports = Service
