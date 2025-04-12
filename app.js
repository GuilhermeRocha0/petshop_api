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

// Open Route - Public Route
app.get('/', (req, res) => {
  res.status(200).json({ msg: 'Bem vindo a PetShop API' })
})

// Register User
app.post('/auth/register', async (req, res) => {
  const { name, cpf, email, password, confirmPassword } = req.body

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
