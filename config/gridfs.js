const multer = require('multer')
const { Readable } = require('stream')
const mongoose = require('mongoose')

const storage = multer.memoryStorage() // usa a memória ao invés de salvar no disco
const upload = multer({ storage })

const uploadToGridFS = async (buffer, filename, mimetype) => {
  const bucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, {
    bucketName: 'productImages'
  })

  const stream = Readable.from(buffer)

  return new Promise((resolve, reject) => {
    const uploadStream = bucket.openUploadStream(filename, {
      contentType: mimetype
    })

    const fileId = uploadStream.id // aqui está o _id do arquivo

    stream
      .pipe(uploadStream)
      .on('error', reject)
      .on('finish', () => {
        resolve(fileId)
      })
  })
}

module.exports = { upload, uploadToGridFS }
