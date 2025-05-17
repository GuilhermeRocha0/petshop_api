const mongoose = require('mongoose')

const AppointmentSchema = new mongoose.Schema({
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
      serviceId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Service',
        required: true
      },
      name: { type: String, required: true },
      price: { type: Number, required: true },
      estimatedTime: { type: Number, required: true }
    }
  ],
  scheduledDate: { type: Date, required: true },
  totalPrice: { type: Number, required: true },
  totalEstimatedTime: { type: Number, required: true },
  status: {
    type: String,
    enum: ['cancelado', 'pendente', 'em andamento', 'a pagar', 'concluído'],
    default: 'pendente'
  },
  createdAt: { type: Date, default: Date.now }
})

module.exports = mongoose.model('Appointment', AppointmentSchema)
