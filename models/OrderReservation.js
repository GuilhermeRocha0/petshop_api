const mongoose = require('mongoose')

const OrderReservationSchema = new mongoose.Schema({
  user: {
    name: { type: String, required: true },
    email: { type: String, required: true },
    cpf: { type: String, required: true }
  },
  items: [
    {
      productId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product',
        required: true
      },
      name: { type: String, required: true },
      description: { type: String },
      price: { type: Number, required: true },
      quantity: { type: Number, required: true }
    }
  ],
  totalAmount: { type: Number, required: true },
  createdAt: { type: Date, default: Date.now },
  validUntil: { type: Date, required: true },
  status: {
    type: String,
    enum: ['pendente', 'concluído', 'cancelado'],
    default: 'pendente'
  }
})

module.exports = mongoose.model('OrderReservation', OrderReservationSchema)
