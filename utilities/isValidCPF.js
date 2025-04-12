function isValidCPF(cpf) {
  if (cpf.length !== 11 || /^(\d)\1+$/.test(cpf)) {
    return false
  }

  let sum = 0
  for (let i = 0; i < 9; i++) {
    sum += parseInt(cpf[i]) * (10 - i)
  }

  let firstDigit = 11 - (sum % 11)
  if (firstDigit >= 10) firstDigit = 0

  if (firstDigit !== parseInt(cpf[9])) {
    return false
  }

  sum = 0
  for (let i = 0; i < 10; i++) {
    sum += parseInt(cpf[i]) * (11 - i)
  }

  let secondDigit = 11 - (sum % 11)
  if (secondDigit >= 10) secondDigit = 0

  return secondDigit === parseInt(cpf[10])
}

module.exports = isValidCPF
