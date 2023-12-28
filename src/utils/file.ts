import fs from 'fs'
import { Request } from 'express'
import formidable, { File } from 'formidable'
import { UPLOAD_IMAGE_DIR, UPLOAD_IMAGE_TEMP_DIR, UPLOAD_VIDEO_DIR } from '~/constants/dir'
import { MediasMessages } from '~/constants/messages'

export const initFolder = () => {
  ;[UPLOAD_IMAGE_DIR, UPLOAD_IMAGE_TEMP_DIR, UPLOAD_VIDEO_DIR].forEach((dir) => {
    if (!fs.existsSync(dir)) {
      // Nếu không tồn tại, tạo thư mục
      fs.mkdirSync(dir, {
        recursive: true // tạo nested folder
      })
    }
  })
}

export const handleUploadImage = async (req: Request) => {
  const form = formidable({
    uploadDir: UPLOAD_IMAGE_TEMP_DIR,
    keepExtensions: true,
    maxFiles: 4,
    maxFileSize: 300 * 1024, // 300 kB,
    maxTotalFileSize: 300 * 1024 * 4, // 1.17 MB,
    filter: function ({ mimetype }) {
      // keep only images
      const valid = mimetype && mimetype.includes('image')
      if (!valid) {
        form.emit('error' as any, new Error(MediasMessages.FileTypeIsNoValid) as any)
        return false
      }
      return true
    }
  })

  return new Promise<File[]>((resolve, reject) => {
    form.parse(req, (err, fields, files) => {
      if (err) {
        return reject(err)
      }

      if (!Object.keys(files).length) {
        return reject(new Error(MediasMessages.FileIsEmpty))
      }
      return resolve(files.image as File[])
    })
  })
}

export const handleUploadVideo = async (req: Request) => {
  const form = formidable({
    uploadDir: UPLOAD_VIDEO_DIR,
    keepExtensions: true,
    maxFiles: 1,
    maxFileSize: 50 * 1024 * 1024, // 50 MB,
    filter: function ({ mimetype }) {
      // // keep only video
      const valid = mimetype && (mimetype.includes('video') || mimetype.includes('quicktime'))
      if (!valid) {
        form.emit('error' as any, new Error(MediasMessages.FileTypeIsNoValid) as any)
        return false
      }
      return true
    }
  })

  return new Promise<File[]>((resolve, reject) => {
    form.parse(req, (err, fields, files) => {
      if (err) {
        return reject(err)
      }

      if (!Object.keys(files).length) {
        return reject(new Error(MediasMessages.FileIsEmpty))
      }

      return resolve(files.video as File[])
    })
  })
}

export const getNameFromFullName = (fullName: string) => {
  const nameArr = fullName.split('.')

  return nameArr[0]
}

export const getExtension = (fullName: string) => {
  const nameArr = fullName.split('.')
  return nameArr[nameArr.length - 1]
}
