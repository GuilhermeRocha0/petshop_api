const mongoose = require('mongoose')

const Appointment = mongoose.model('Appointment', {
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pet: {
    petId: { type: mongoose.Schema.Types.ObjectId, ref: 'Pet', required: true },
    name: { type: String, required: true },
    size: { type: String, required: true },
    age: { type: Number, required: true },
    breed: { type: String, required: true },
    notes: { type: String }
  },
  services: [
    {
      name: { type: String, required: true },
      price: { type: Number, required: true },
      estimatedTime: { type: Number, required: true } // Tempo estimado em minutos
    }
  ],
  scheduledDate: { type: Date, required: true },
  totalPrice: { type: Number, required: true },
  totalEstimatedTime: { type: Number, required: true }, // Tempo total estimado em minutos
  status: {
    type: String,
    enum: ['cancelado', 'pendente', 'em andamento', 'a pagar', 'concluído'],
    default: 'pendente'
  },
  createdAt: { type: Date, default: Date.now }
})

module.exports = Appointment
