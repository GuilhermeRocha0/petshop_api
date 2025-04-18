const User = require('../models/User')

const checkAdminOrEmployee = async (req, res, next) => {
  try {
    const user = await User.findById(req.userId)

    if (!user || (user.role !== 'ADMIN' && user.role !== 'EMPLOYEE')) {
      return res.status(403).json({ msg: 'Acesso negado!' })
    }

    next()
  } catch (error) {
    console.log(error)
    return res.status(500).json({ msg: 'Erro ao verificar permissão!' })
  }
}

module.exports = checkAdminOrEmployee
