require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Config JSON response
app.use(express.json())

// Models
const User = require('./models/User')

// Utilites
const isValidCPF = require('./utilities/isValidCPF')

// Middlewares
const checkToken = require('./middlewares/checkToken')

// Open Route - Public Route
app.get('/', (req, res) => {
  res.status(200).json({ msg: 'Bem vindo a PetShop API' })
})

// Private Route
app.get('/user/:id', checkToken, (req, res) => {
  const id = req.params.id

  // check if user exists
  User.findById(id, '-password -cpf')
    .then(user => {
      return res.status(200).json({ user })
    })
    .catch(error => {
      return res.status(404).json({ msg: 'Usuário não encontrado!' })
    })
})

// Register User
app.post('/auth/register', async (req, res) => {
  const { name, email, password, confirmPassword } = req.body
  let { cpf } = req.body

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

  if (!password) {
    return res.status(422).json({ msg: 'A senha é obrigatória!' })
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
    password: passwordHash
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

  // validations
  if (!email) {
    return res.status(422).json({ msg: 'O email é obrigatório!' })
  }

  if (!password) {
    return res.status(422).json({ msg: 'A senha é obrigatória!' })
  }

  // check if user exists
  const user = await User.findOne({ email: email })
  if (!user) {
    return res.status(404).json({ msg: 'Usuário não encontrado!' })
  }

  // check if password match
  const checkPassword = await bcrypt.compare(password, user.password)
  if (!checkPassword) {
    return res.status(404).json({ msg: 'Senha inválida!' })
  }

  try {
    const secret = process.env.secret

    const token = jwt.sign(
      {
        id: user._id
      },
      secret
    )

    res.status(200).json({ msg: 'Autenticação realizada com sucesso!', token })
  } catch (error) {
    console.log(error)

    res
      .status(500)
      .json({ msg: 'Ocorreu um erro no servidor, tente novamente mais tarde!' })
  }
})

// Update User
app.put('/user/:id', checkToken, async (req, res) => {
  const id = req.params.id
  const { name, email } = req.body

  // validations
  if (!email) {
    return res.status(422).json({ msg: 'O email é obrigatório!' })
  }

  if (!password) {
    return res.status(422).json({ msg: 'A senha é obrigatória!' })
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
