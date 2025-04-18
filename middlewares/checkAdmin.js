const User = require('../models/User')

async function checkAdmin(req, res, next) {
  try {
    const user = await User.findById(req.userId)

    if (!user || user.role !== 'ADMIN') {
      return res
        .status(403)
        .json({
          msg: 'Acesso negado! Apenas administradores podem realizar essa ação.'
        })
    }

    next()
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro no servidor!' })
  }
}

module.exports = checkAdmin
