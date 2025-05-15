require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const Grid = require('gridfs-stream')
const cors = require('cors')

const app = express()

app.use(cors())

// Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')
const Pet = require('./models/Pet')
const Service = require('./models/Service')
const Appointment = require('./models/Appointment')
const PasswordResetToken = require('./models/PasswordResetToken')
const Category = require('./models/Category')
const Product = require('./models/Product')

// Utilites
const isValidCPF = require('./utilities/isValidCPF')
const isValidEmail = require('./utilities/isValidEmail')
const isValidPassword = require('./utilities/isValidPassword')
const sendEmail = require('./utilities/sendEmail')

// Conifg
const { upload, uploadToGridFS } = require('./config/gridfs')

// Middlewares
const checkToken = require('./middlewares/checkToken')
const checkAdmin = require('./middlewares/checkAdmin')
const checkAdminOrEmployee = require('./middlewares/checkAdminOrEmployee')

// Open Route - Public Route
app.get('/', (req, res) => {
  res.status(200).json({ msg: 'Bem vindo a PetShop API' })
})

// Show User Data
app.get('/user/:id', checkToken, (req, res) => {
  const id = req.params.id

  // check if user exists
  User.findById(id, '-password')
    .then(user => {
      if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
      }
      return res.status(200).json({ user })
    })
    .catch(error => {
      return res.status(500).json({ msg: 'Erro no servidor!' })
    })
})

// Register User
app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body
  let { cpf } = req.body
  const role = 'CUSTOMER'

  // validations
  if (!name) {
    return res.status(422).json({ msg: 'O nome é obrigatório!' })
  }

  if (!cpf) {
    return res.status(422).json({ msg: 'O CPF é obrigatório!' })
  }

  if (!email) {
    return res.status(422).json({ msg: 'O email é obrigatório!' })
  }

  // Validate email format
  if (!isValidEmail(email)) {
    return res.status(422).json({ msg: 'Email inválido!' })
  }

  if (!password) {
    return res.status(422).json({ msg: 'A senha é obrigatória!' })
  }

  // Validate password strength
  if (!isValidPassword(password)) {
    return res.status(422).json({
      msg: 'A senha deve ter pelo menos 8 caracteres, uma letra maiúscula, uma minúscula, um número e um caractere especial!'
    })
  }

  if (password !== confirmPassword) {
    return res.status(422).json({ msg: 'As senhas não conferem!' })
  }

  // check if cpf is valid
  cpf = cpf.replace(/[^\d]+/g, '')
  if (!isValidCPF(cpf)) {
    return res.status(422).json({ msg: 'CPF inválido, utilize um CPF válido!' })
  }

  // check if user exists
  const userExists = await User.findOne({ email: email })
  if (userExists) {
    return res.status(422).json({ msg: 'Usuário com este email já existe!' })
  }

  // create password
  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(password, salt)

  // create user
  const user = new User({
    name,
    cpf,
    email,
    password: passwordHash,
    role
  })

  try {
    await user.save()

    res.status(201).json({ msg: 'Usuário criado com sucesso!' })
  } catch (error) {
    console.log(error)

    res
      .status(500)
      .json({ msg: 'Ocorreu um erro no servidor, tente novamente mais tarde!' })
  }
})

// Login User
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body

  if (!email) {
    return res.status(422).json({ msg: 'O email é obrigatório!' })
  }

  if (!password) {
    return res.status(422).json({ msg: 'A senha é obrigatória!' })
  }

  try {
    const user = await User.findOne({ email })

    if (!user) {
      return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    const checkPassword = await bcrypt.compare(password, user.password)
    if (!checkPassword) {
      return res.status(404).json({ msg: 'Senha inválida!' })
    }

    const token = jwt.sign({ id: user._id }, process.env.SECRET, {
      expiresIn: '1h'
    })

    return res.status(200).json({
      msg: 'Autenticação realizada com sucesso!',
      token,
      user: {
        id: user._id,
        role: user.role
      }
    })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro no servidor!' })
  }
})

// Forgot Password
app.post('/auth/forgot-password', async (req, res) => {
  const { email } = req.body

  if (!email) {
    return res.status(422).json({ msg: 'O email é obrigatório!' })
  }

  const user = await User.findOne({ email })
  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado!' })
  }

  const code = Math.floor(100000 + Math.random() * 900000).toString()

  const expiresAt = new Date()
  expiresAt.setMinutes(expiresAt.getMinutes() + 30) // código válido por 30 min

  await PasswordResetToken.deleteMany({ userId: user._id }) // limpa códigos antigos

  const resetToken = new PasswordResetToken({
    userId: user._id,
    code,
    expiresAt
  })
  await resetToken.save()

  await sendEmail(user.email, 'Código de recuperação', `Seu código é: ${code}`)

  return res.status(200).json({ msg: 'Código enviado para seu email!' })
})

// Verify Code (to Reset Password)
app.post('/auth/verify-code', async (req, res) => {
  const { email, code } = req.body

  if (!email || !code) {
    return res.status(422).json({ msg: 'Email e código são obrigatórios!' })
  }

  const user = await User.findOne({ email })
  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado!' })
  }

  const token = await PasswordResetToken.findOne({
    userId: user._id,
    code
  })

  if (!token || token.expiresAt < new Date()) {
    return res.status(400).json({ msg: 'Código inválido ou expirado!' })
  }

  return res.status(200).json({ msg: 'Código verificado com sucesso!' })
})

// Reset Password
app.post('/auth/reset-password', async (req, res) => {
  const { email, code, newPassword, confirmPassword } = req.body

  if (!email || !code || !newPassword || !confirmPassword) {
    return res.status(422).json({ msg: 'Preencha todos os campos!' })
  }

  if (newPassword !== confirmPassword) {
    return res.status(422).json({ msg: 'As senhas não conferem!' })
  }

  if (!isValidPassword(newPassword)) {
    return res.status(422).json({
      msg: 'A senha deve conter ao menos 8 caracteres, com letra maiúscula, minúscula, número e símbolo.'
    })
  }

  const user = await User.findOne({ email })
  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado!' })
  }

  const token = await PasswordResetToken.findOne({ userId: user._id, code })
  if (!token || token.expiresAt < new Date()) {
    return res.status(400).json({ msg: 'Código inválido ou expirado!' })
  }

  const salt = await bcrypt.genSalt(12)
  const passwordHash = await bcrypt.hash(newPassword, salt)
  user.password = passwordHash
  await user.save()

  await PasswordResetToken.deleteMany({ userId: user._id })

  return res.status(200).json({ msg: 'Senha redefinida com sucesso!' })
})

// Update User (name, email, cpf)
app.put('/user/edit', checkToken, async (req, res) => {
  const id = req.userId // vem do token
  const { name, email } = req.body
  let { cpf } = req.body

  // validations
  if (!name) {
    return res.status(422).json({ msg: 'O nome é obrigatório!' })
  }

  if (!email) {
    return res.status(422).json({ msg: 'O email é obrigatório!' })
  }

  if (!cpf) {
    return res.status(422).json({ msg: 'O CPF é obrigatório!' })
  }

  // check if cpf is valid
  cpf = cpf.replace(/[^\d]+/g, '')
  if (!isValidCPF(cpf)) {
    return res.status(422).json({ msg: 'CPF inválido, utilize um CPF válido!' })
  }

  try {
    // check if user exists
    const user = await User.findById(id, '-password -cpf')

    if (!user) {
      return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    // update user data
    user.name = name
    user.email = email

    const updatedUser = await user.save()

    return res.status(200).json({
      msg: 'Usuário atualizado com sucesso!',
      user: {
        id: updatedUser._id,
        name: updatedUser.name,
        email: updatedUser.email
      }
    })
  } catch (error) {
    console.log(error)
    return res
      .status(500)
      .json({ msg: 'Ocorreu um erro no servidor, tente novamente mais tarde!' })
  }
})

// Update User (password)
app.put('/user/change-password', checkToken, async (req, res) => {
  const { currentPassword, newPassword, confirmNewPassword } = req.body
  const id = req.userId // vem do token

  if (!currentPassword || !newPassword || !confirmNewPassword) {
    return res.status(422).json({ msg: 'Preencha todos os campos!' })
  }

  if (newPassword !== confirmNewPassword) {
    return res.status(422).json({ msg: 'As novas senhas não conferem!' })
  }

  // Validate new password strength
  if (!isValidPassword(newPassword)) {
    return res.status(422).json({
      msg: 'A senha deve ter pelo menos 8 caracteres, uma letra maiúscula, uma minúscula, um número e um caractere especial!'
    })
  }

  try {
    const user = await User.findById(id)
    if (!user) {
      return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    const isPasswordCorrect = await bcrypt.compare(
      currentPassword,
      user.password
    )
    if (!isPasswordCorrect) {
      return res.status(401).json({ msg: 'Senha atual incorreta!' })
    }

    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(newPassword, salt)

    user.password = passwordHash
    await user.save()

    return res.status(200).json({ msg: 'Senha alterada com sucesso!' })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro no servidor!' })
  }
})

// Register Pet
app.post('/pets/register', checkToken, async (req, res) => {
  const { name, size, age, breed, notes } = req.body
  const userId = req.userId

  if (!name || !size || typeof age !== 'number' || isNaN(age) || !breed) {
    return res
      .status(422)
      .json({ msg: 'Todos os campos obrigatórios devem ser preenchidos!' })
  }

  if (age < 0) {
    return res.status(422).json({ msg: 'Idade inválida!' })
  }

  if (!['pequeno', 'médio', 'grande'].includes(size)) {
    return res
      .status(422)
      .json({ msg: 'Porte inválido! Use: pequeno, médio ou grande.' })
  }

  const pet = new Pet({
    userId,
    name,
    size,
    age,
    breed,
    notes
  })

  const existingPet = await Pet.findOne({ name, userId })

  if (existingPet) {
    return res
      .status(400)
      .json({ msg: 'Você já cadastrou um pet com esse nome.' })
  }

  try {
    await pet.save()
    res.status(201).json({ msg: 'Pet cadastrado com sucesso!', pet })
  } catch (error) {
    console.log(error)
    res.status(500).json({ msg: 'Erro ao cadastrar o pet!' })
  }
})

// Show all User Pets
app.get('/pets', checkToken, async (req, res) => {
  const userId = req.userId

  try {
    const pets = await Pet.find({ userId })

    return res.status(200).json({ pets })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao buscar os pets!' })
  }
})

// Update Pet
app.put('/pets/:id/edit', checkToken, async (req, res) => {
  const petId = req.params.id
  const userId = req.userId
  const { name, size, age, breed, notes } = req.body

  if (!name || !size || isNaN(age) || !breed) {
    return res
      .status(422)
      .json({ msg: 'Todos os campos obrigatórios devem ser preenchidos!' })
  }

  if (age < 0) {
    return res.status(422).json({ msg: 'Idade inválida!' })
  }

  if (!['pequeno', 'médio', 'grande'].includes(size)) {
    return res
      .status(422)
      .json({ msg: 'Porte inválido! Use: pequeno, médio ou grande.' })
  }

  try {
    // Verifica se o pet existe e pertence ao usuário
    const pet = await Pet.findOne({ _id: petId, userId })

    if (!pet) {
      return res
        .status(404)
        .json({ msg: 'Pet não encontrado ou não pertence a este usuário!' })
    }

    pet.name = name
    pet.size = size
    pet.age = age
    pet.breed = breed
    pet.notes = notes

    await pet.save()

    return res.status(200).json({ msg: 'Pet atualizado com sucesso!', pet })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao atualizar o pet!' })
  }
})

// Delete Pet
app.delete('/pets/:id', checkToken, async (req, res) => {
  const { id } = req.params

  try {
    const pet = await Pet.findOne({ _id: id, userId: req.userId })
    if (!pet) {
      return res.status(404).json({ msg: 'Pet não encontrado!' })
    }

    await Pet.deleteOne({ _id: id })
    return res.status(200).json({ msg: 'Pet deletado com sucesso!' })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao deletar pet!' })
  }
})

// Register Service
app.post('/services/register', checkToken, checkAdmin, async (req, res) => {
  const { name, price, estimatedTime } = req.body

  if (!name || !price || !estimatedTime) {
    return res
      .status(422)
      .json({ msg: 'Preencha todos os campos obrigatórios!' })
  }

  const service = new Service({
    name,
    price,
    estimatedTime
  })

  try {
    await service.save()
    return res
      .status(201)
      .json({ msg: 'Serviço cadastrado com sucesso!', service })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao cadastrar o serviço!' })
  }
})

// Show Services
app.get('/services', async (req, res) => {
  try {
    const services = await Service.find()

    if (!services || services.length === 0) {
      return res.status(404).json({ msg: 'Nenhum serviço encontrado!' })
    }

    return res.status(200).json({ services })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao buscar os serviços!' })
  }
})

// Update Service
app.put('/services/:id', checkToken, checkAdmin, async (req, res) => {
  const serviceId = req.params.id
  const { name, price, estimatedTime } = req.body

  if (!name || !price || !estimatedTime) {
    return res
      .status(422)
      .json({ msg: 'Preencha todos os campos obrigatórios!' })
  }

  try {
    const service = await Service.findById(serviceId)

    if (!service) {
      return res.status(404).json({ msg: 'Serviço não encontrado!' })
    }

    service.name = name
    service.price = price
    service.estimatedTime = estimatedTime

    await service.save()

    return res
      .status(200)
      .json({ msg: 'Serviço atualizado com sucesso!', service })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao atualizar o serviço!' })
  }
})

// Delete Service
app.delete('/services/:id', checkToken, checkAdmin, async (req, res) => {
  const serviceId = req.params.id

  try {
    const service = await Service.findByIdAndDelete(serviceId)

    if (!service) {
      return res.status(404).json({ msg: 'Serviço não encontrado!' })
    }

    return res.status(200).json({ msg: 'Serviço excluído com sucesso!' })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao excluir o serviço!' })
  }
})

// Show All Appointments
app.get('/appointments/all', checkToken, checkAdmin, async (req, res) => {
  try {
    const appointments = await Appointment.find()
      .sort({ scheduledDate: 1 })
      .populate('userId', 'name email')

    if (appointments.length === 0) {
      return res.status(404).json({ msg: 'Nenhum agendamento encontrado!' })
    }

    return res.status(200).json({ appointments })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao buscar agendamentos!' })
  }
})

// Show User Appointments
app.get('/appointments', checkToken, async (req, res) => {
  try {
    const appointments = await Appointment.find({ userId: req.userId })
    return res.status(200).json({ appointments })
  } catch (error) {
    console.error(error)
    return res.status(500).json({ msg: 'Erro ao carregar agendamentos.' })
  }
})

// Register Appointment
app.post('/appointments', checkToken, async (req, res) => {
  const { petId, serviceIds, scheduledDate } = req.body

  if (!petId || !serviceIds || !scheduledDate) {
    return res
      .status(422)
      .json({ msg: 'Preencha todos os campos obrigatórios!' })
  }

  try {
    // Valida o pet
    const pet = await Pet.findOne({ _id: petId, userId: req.userId })
    if (!pet) {
      return res.status(404).json({ msg: 'Pet não encontrado!' })
    }

    // Busca os serviços selecionados
    const services = await Service.find({ _id: { $in: serviceIds } })
    if (services.length !== serviceIds.length) {
      return res
        .status(404)
        .json({ msg: 'Um ou mais serviços não encontrados!' })
    }

    // Calcula o total de preço e tempo
    const totalPrice = services.reduce((acc, s) => acc + s.price, 0)
    const totalEstimatedTime = services.reduce(
      (acc, s) => acc + s.estimatedTime,
      0
    )

    // Cria a lista de serviços para o agendamento
    const fixedServices = services.map(s => ({
      name: s.name,
      price: s.price,
      estimatedTime: s.estimatedTime
    }))

    // Cria o agendamento com o status padrão "pendente"
    const appointment = new Appointment({
      userId: req.userId,
      pet: {
        petId: pet._id,
        name: pet.name,
        size: pet.size,
        age: pet.age,
        breed: pet.breed,
        notes: pet.notes
      },
      services: fixedServices,
      scheduledDate,
      totalPrice,
      totalEstimatedTime,
      status: 'pendente' // Status padrão
    })

    await appointment.save()

    // Envia e-mail automático
    const user = await User.findById(req.userId)
    if (user && user.email) {
      const serviceList = fixedServices
        .map(s => `<li>${s.name} - R$${s.price.toFixed(2)}</li>`)
        .join('')

      await sendEmail(
        user.email,
        '📅 Agendamento confirmado - PetDaCarla',
        `
          <p>Olá ${user.name}! Como vai?</p>
          <p>Seu agendamento para o <strong>${
            pet.name
          }</strong> foi confirmado com sucesso!</p>
          <p><strong>Data:</strong> ${new Date(scheduledDate).toLocaleString(
            'pt-BR'
          )}</p>
          <p><strong>Serviço contratado:</strong></p>
          <ul>${serviceList}</ul>
          <p><strong>Preço total:</strong> R$${totalPrice.toFixed(2)}</p>
          <p>Obrigado por escolher o PetDaCarla! Seu cachorrinho vai te agradecer com muitas lambidas! 🐶</p>
        `
      )
    }
    return res
      .status(201)
      .json({ msg: 'Agendamento realizado com sucesso!', appointment })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao realizar o agendamento!' })
  }
})

// Cancel Appointment
app.put('/appointments/cancel/:id', checkToken, async (req, res) => {
  const appointmentId = req.params.id

  try {
    // Verifica se o agendamento existe e pertence ao usuário
    const appointment = await Appointment.findOne({
      _id: appointmentId,
      userId: req.userId
    })

    if (!appointment) {
      return res.status(404).json({
        msg: 'Agendamento não encontrado ou você não tem permissão para cancelar!'
      })
    }

    // Verifica se o agendamento já foi cancelado
    if (appointment.status === 'cancelado') {
      return res
        .status(400)
        .json({ msg: 'Este agendamento já está cancelado!' })
    }

    // Atualiza o status para "cancelado"
    appointment.status = 'cancelado'
    await appointment.save()

    // Envia e-mail de cancelamento
    const user = await User.findById(req.userId)

    const emailHTML = `
      <p>Olá ${user.name}! Como vai?</p>
      <p>Seu agendamento para o <strong>${
        appointment.pet.name
      }</strong> foi <strong>cancelado</strong>.</p>
      <p><strong>Data originalmente agendada:</strong> ${new Date(
        appointment.scheduledDate
      ).toLocaleString('pt-BR')}</p>
      <p><strong>Serviço cancelado:</strong></p>
      <ul>
        ${appointment.services
          .map(s => `<li>${s.name} - R$${s.price.toFixed(2)}</li>`)
          .join('')}
      </ul>
      <p><strong>Preço total:</strong> R$${appointment.totalPrice.toFixed(
        2
      )}</p>
      <p>Se foi um engano, entre em contato conosco para reagendar.</p>
      <p>Atenciosamente,<br>PetDaCarla 🐾</p>
    `

    await sendEmail(
      user.email,
      '❌ Agendamento cancelado - PetDaCarla',
      emailHTML
    )

    return res
      .status(200)
      .json({ msg: 'Agendamento cancelado com sucesso!', appointment })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao cancelar o agendamento!' })
  }
})

// Update Appointment status (ADMIN or EMPLOYEE only)
app.put(
  '/appointments/status/:id',
  checkToken,
  checkAdmin,
  async (req, res) => {
    const appointmentId = req.params.id
    const { status } = req.body

    const validStatus = ['em andamento', 'a pagar', 'concluído']

    if (!validStatus.includes(status)) {
      return res.status(400).json({
        msg: `Status inválido! Só é permitido: ${validStatus.join(', ')}.`
      })
    }

    try {
      const appointment = await Appointment.findById(appointmentId)
      if (!appointment) {
        return res.status(404).json({ msg: 'Agendamento não encontrado!' })
      }

      if (appointment.status === 'cancelado') {
        return res.status(403).json({
          msg: 'Este agendamento foi cancelado e não pode ser alterado.'
        })
      }

      appointment.status = status
      await appointment.save()

      return res
        .status(200)
        .json({ msg: 'Status atualizado com sucesso!', appointment })
    } catch (error) {
      console.log(error)
      return res
        .status(500)
        .json({ msg: 'Erro ao atualizar o status do agendamento!' })
    }
  }
)

// Get Categories
app.get('/categories', async (req, res) => {
  try {
    const categories = await Category.find()
    return res.status(200).json(categories)
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao buscar categorias!' })
  }
})

// Register Category
app.post('/categories', checkToken, checkAdmin, async (req, res) => {
  const { name } = req.body

  if (!name) {
    return res.status(422).json({ msg: 'Nome da categoria é obrigatório!' })
  }

  try {
    const category = new Category({ name })
    await category.save()

    return res
      .status(201)
      .json({ msg: 'Categoria criada com sucesso!', category })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao criar categoria!' })
  }
})

// Update Category
app.put('/categories/:id', checkToken, checkAdmin, async (req, res) => {
  try {
    const { name } = req.body

    if (!name || name.trim() === '') {
      return res.status(400).json({ msg: 'Nome da categoria é obrigatório' })
    }

    const category = await Category.findByIdAndUpdate(
      req.params.id,
      { name },
      { new: true }
    )

    if (!category) {
      return res.status(404).json({ msg: 'Categoria não encontrada' })
    }

    return res.status(200).json({ msg: 'Categoria atualizada', category })
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao atualizar categoria' })
  }
})

// Register Product
app.post(
  '/products',
  checkToken,
  checkAdmin,
  upload.single('image'),
  async (req, res) => {
    try {
      const { name, description, price, quantity, category } = req.body

      if (!req.file) {
        return res.status(400).json({ msg: 'Imagem do produto é obrigatória!' })
      }

      if (quantity < 0) {
        return res
          .status(400)
          .json({ msg: 'Quantidade não pode ser menor que 0' })
      }

      // valida categoria
      const categoryExists = await Category.findById(category)
      if (!categoryExists) {
        return res.status(404).json({ msg: 'Categoria não encontrada' })
      }

      // faz upload da imagem para o GridFS
      const imageId = await uploadToGridFS(
        req.file.buffer,
        req.file.originalname,
        req.file.mimetype
      )

      const product = new Product({
        name,
        description,
        price,
        quantity,
        category,
        image: imageId.toString()
      })

      await product.save()

      return res
        .status(201)
        .json({ msg: 'Produto criado com sucesso!', product })
    } catch (error) {
      console.log(error)
      return res.status(500).json({ msg: 'Erro ao cadastrar produto' })
    }
  }
)

// Update Product
app.put(
  '/products/:id',
  checkToken,
  checkAdmin,
  upload.single('image'),
  async (req, res) => {
    try {
      const { name, description, price, quantity, category } = req.body

      const updates = {}

      if (name) updates.name = name
      if (description) updates.description = description
      if (price) updates.price = price
      if (quantity < 0) {
        return res.status(400).json({ msg: 'Quantidade não pode ser negativa' })
      }
      if (quantity !== undefined) updates.quantity = quantity

      if (category) {
        const categoryExists = await Category.findById(category)
        if (!categoryExists) {
          return res.status(404).json({ msg: 'Categoria não encontrada' })
        }
        updates.category = category
      }

      if (req.file) {
        const imageId = await uploadToGridFS(
          req.file.buffer,
          req.file.originalname,
          req.file.mimetype
        )
        updates.image = imageId.toString()
      }

      const updatedProduct = await Product.findByIdAndUpdate(
        req.params.id,
        updates,
        { new: true }
      )

      if (!updatedProduct) {
        return res.status(404).json({ msg: 'Produto não encontrado' })
      }

      return res
        .status(200)
        .json({ msg: 'Produto atualizado com sucesso', updatedProduct })
    } catch (error) {
      console.log(error)
      return res.status(500).json({ msg: 'Erro ao atualizar produto' })
    }
  }
)

// Get Product Image
app.get('/products/image/:id', async (req, res) => {
  try {
    const file = await mongoose.connection.db
      .collection('productImages.files')
      .findOne({ _id: new mongoose.Types.ObjectId(req.params.id) })

    if (!file || !file.contentType.startsWith('image/')) {
      return res.status(404).json({ msg: 'Imagem não encontrada' })
    }

    const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
      bucketName: 'productImages'
    })

    const readStream = bucket.openDownloadStream(
      new mongoose.Types.ObjectId(req.params.id)
    )
    res.set('Content-Type', file.contentType)
    return readStream.pipe(res)
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao buscar imagem' })
  }
})

// Get Products
app.get('/products', async (req, res) => {
  try {
    const products = await Product.find().populate('category', 'name')

    const updatedProducts = products.map(product => ({
      _id: product._id,
      name: product.name,
      description: product.description,
      price: product.price,
      quantity: product.quantity,
      category: product.category,
      imageUrl: `/products/image/${product.image}` // gera o link da imagem
    }))

    return res.status(200).json(updatedProducts)
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao buscar produtos' })
  }
})

// Get Product
app.get('/products/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id).populate(
      'category',
      'name'
    )

    if (!product) {
      return res.status(404).json({ msg: 'Produto não encontrado' })
    }

    const productData = {
      _id: product._id,
      name: product.name,
      description: product.description,
      price: product.price,
      quantity: product.quantity,
      category: product.category,
      imageUrl: `/products/image/${product.image}`
    }

    return res.status(200).json(productData)
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao buscar produto' })
  }
})

// Credentials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.9e7tkyp.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
  )
  .then(() => {
    console.log('Conectou ao banco!')
  })
  .catch(err => {
    console.log(err)
  })

app.listen(3000)
