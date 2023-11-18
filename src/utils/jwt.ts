import jwt from 'jsonwebtoken'
import 'dotenv/config'

export function signToken({
  payload,
  privateKey = process.env.JWT_SECRET as string,
  options = {
    algorithm: 'HS256'
  }
}: {
  payload: string | Buffer | object
  privateKey?: string
  options?: jwt.SignOptions
}) {
  return new Promise<string>((resolve, reject) => {
    jwt.sign(payload, privateKey, options, function (error, token) {
      if (error) throw reject(error)
      resolve(token as string)
    })
  })
}