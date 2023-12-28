import { NextFunction, Request, Response } from 'express'
import { ParamSchema, checkSchema } from 'express-validator'
import { HttpStatusCode, UserVerifyStatus } from '~/constants/enums'
import { ErrorWithStatus } from '~/models/Errors'
import userService from '~/services/users.services'
import { verifyToken } from '~/utils/jwt'
import { validate } from '~/utils/validation'
import { JsonWebTokenError } from 'jsonwebtoken'
import capitalize from 'lodash/capitalize'
import databaseService from '~/services/database.services'
import { ObjectId } from 'mongodb'
import { ChangePasswordReqBody, TokenPayload } from '~/models/requests/User.requests'
import { REGEX_USERNAME } from '~/constants/regex'
import { hashPassword } from '~/utils/crypto'
import { UsersMessages } from '~/constants/messages'
import { verifyAccessToken } from '~/utils/commons'
import { envConfig } from '~/constants/config'

// Chứa các file chứa các hàm xử lý middleware, như validate, check token, ...

const nameSchema: ParamSchema = {
  notEmpty: { bail: true, errorMessage: UsersMessages.NameIsRequired },
  isString: { bail: true, errorMessage: UsersMessages.NameMustBeAString },
  trim: true,
  isLength: {
    options: { max: 100, min: 1 }
  }
}

const dateOfBirthSchema: ParamSchema = {
  isISO8601: {
    options: {
      strict: true,
      strictSeparator: true
    },
    errorMessage: UsersMessages.DateOfBirthMustBeISO8601
  }
}

const imageSchema: ParamSchema = {
  optional: true,
  isString: {
    errorMessage: UsersMessages.ImageURLMustBeAString
  },
  trim: true,
  isLength: {
    options: {
      min: 1,
      max: 400
    },
    errorMessage: UsersMessages.ImageURLLengthRequired
  }
}

const passwordSchema: ParamSchema = {
  notEmpty: { bail: true, errorMessage: UsersMessages.PasswordIsRequired },
  isString: { bail: true, errorMessage: UsersMessages.PasswordMustBeAString },
  isLength: {
    options: { min: 6, max: 50 },
    bail: true,
    errorMessage: UsersMessages.PasswordLengthRequired
  },
  isStrongPassword: {
    options: { minLength: 6, minLowercase: 1, minUppercase: 1, minNumbers: 1, minSymbols: 1 },
    errorMessage: UsersMessages.PasswordMustBeStrong
  },
  trim: true
}

const userIdSchema: ParamSchema = {
  custom: {
    options: async (value, { req }) => {
      // Kiểm tra tính hợp lệ của _id gửi lên từ request
      if (!ObjectId.isValid(value)) {
        throw new ErrorWithStatus({
          message: UsersMessages.InvalidUserId,
          status: HttpStatusCode.NotFound
        })
      }

      const followedUser = await databaseService.users.findOne({ _id: new ObjectId(value) })

      // Kiểm tra sự tồn tại của user trong database
      if (followedUser === null) {
        throw new ErrorWithStatus({
          message: UsersMessages.UserNotFound,
          status: HttpStatusCode.NotFound
        })
      }

      return true
    }
  }
}

const confirmPasswordSchema: ParamSchema = {
  notEmpty: { errorMessage: UsersMessages.ConfirmPasswordIsRequired },
  isString: { errorMessage: UsersMessages.ConfirmPasswordMustBeAString },
  custom: {
    options: (value, { req }) => {
      if (value !== req.body.password) {
        throw new Error(UsersMessages.PasswordsDoNotMatch)
      }
      return true
    }
  }
}

const forgotPasswordTokenSchema: ParamSchema = {
  trim: true,
  custom: {
    options: async (value, { req }) => {
      // Kiểm tra forgot password token có được gửi cùng request method POST hay chưa?
      if (!value)
        throw new ErrorWithStatus({
          message: UsersMessages.ForgotPasswordTokenIsRequired,
          status: HttpStatusCode.Unauthorized
        })

      try {
        // Decoded forgot password token được gửi từ client
        const decodedForgotPasswordToken = await verifyToken({
          token: value,
          secretOrPublicKey: envConfig.jwtSecretForgotPasswordToken
        })

        // Destructuring payload của forgot password token
        const { user_id } = decodedForgotPasswordToken

        const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })

        if (!user) {
          throw new ErrorWithStatus({
            message: UsersMessages.UserNotFound,
            status: HttpStatusCode.NotFound
          })
        }

        if (user.forgot_password_token !== value) {
          throw new ErrorWithStatus({
            message: UsersMessages.ForgotPasswordTokenIsInvalid,
            status: HttpStatusCode.Unauthorized
          })
        }

        req.decoded_forgot_password_token = decodedForgotPasswordToken

        return true
      } catch (error) {
        // Lỗi truyền refresh token sai định dạng trả về bởi verifyToken
        if (error instanceof JsonWebTokenError) {
          throw new ErrorWithStatus({
            message: capitalize(error.message),
            status: HttpStatusCode.Unauthorized
          })
        }
        throw error
      }
    }
  }
}

export const loginValidator = validate(
  checkSchema(
    {
      email: {
        notEmpty: { bail: true, errorMessage: UsersMessages.EmailIsRequired },
        isEmail: { bail: true, errorMessage: UsersMessages.EmailIsInvalid },
        custom: {
          options: async (value, { req }) => {
            const user = await userService.checkUserExist({ email: value, password: req.body.password })

            if (user === null) {
              throw new Error(UsersMessages.EmailOrPasswordIsIncorrect)
            }

            // set user info vào request
            ;(req as Request).user = user
            return true
          }
        },
        trim: true
      },
      password: passwordSchema
    },
    ['body']
  )
)

export const registerValidator = validate(
  checkSchema(
    {
      name: nameSchema,
      email: {
        notEmpty: { bail: true, errorMessage: UsersMessages.EmailIsRequired },
        isEmail: { bail: true, errorMessage: UsersMessages.EmailIsInvalid },
        custom: {
          options: async (value) => {
            const isEmailExist = await userService.checkEmailExist(value)
            if (isEmailExist) {
              throw new Error(UsersMessages.EmailAlreadyExists)
            }
            return true
          }
        },
        trim: true
      },
      password: passwordSchema,

      confirm_password: confirmPasswordSchema,
      date_of_birth: dateOfBirthSchema
    },
    ['body']
  )
)

export const accessTokenValidator = validate(
  checkSchema(
    {
      Authorization: {
        trim: true,
        custom: {
          options: async (value: string, { req }) => {
            // lấy ra access token từ Headers được gửi đi khi user logout
            const access_token = value.split(' ')[1]
            return await verifyAccessToken(access_token, req as Request)
          }
        }
      }
    },
    ['headers']
  )
)

export const refreshTokenValidator = validate(
  checkSchema(
    {
      refresh_token: {
        trim: true,
        custom: {
          options: async (value, { req }) => {
            // Kiểm tra refresh token có được gửi cùng request method POST hay chưa?
            if (!value)
              throw new ErrorWithStatus({
                message: UsersMessages.RefreshTokenIsRequired,
                status: HttpStatusCode.Unauthorized
              })
            try {
              // Decoded refresh token được gửi từ client & kiểm tra tồn tại của refresh token đó trong database (Nếu true thì xóa luôn trong DB)
              const [decodedRefreshToken, refresh_token] = await Promise.all([
                verifyToken({ token: value, secretOrPublicKey: envConfig.jwtSecretRefreshToken }),
                userService.checkAndDeleteRefreshTokenInDB(value)
              ])

              // Lỗi không tồn tại refresh token trong database
              if (refresh_token === null) {
                throw new ErrorWithStatus({
                  message: UsersMessages.UsedRefreshTokenOrNotExist,
                  status: HttpStatusCode.Unauthorized
                })
              }

              // set decoded refresh token vào req
              ;(req as Request).decoded_refresh_token = decodedRefreshToken

              return true
            } catch (error) {
              // Lỗi truyền refresh token sai định dạng trả về bởi verifyToken
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: capitalize(error.message),
                  status: HttpStatusCode.Unauthorized
                })
              }
              throw error
            }
          }
        }
      }
    },
    ['body']
  )
)

export const emailVerifyTokenValidator = validate(
  checkSchema(
    {
      email_verify_token: {
        trim: true,
        custom: {
          options: async (value, { req }) => {
            // Kiểm tra email verify token có được gửi cùng request method POST hay chưa?
            if (!value)
              throw new ErrorWithStatus({
                message: UsersMessages.EmailVerifyTokenIsRequired,
                status: HttpStatusCode.Unauthorized
              })

            try {
              // Decoded email verify token được gửi từ client
              const decodedEmailVerifyToken = await verifyToken({
                token: value,
                secretOrPublicKey: envConfig.jwtSecretEmailVerifyToken
              })

              // set decoded email verify token vào req
              ;(req as Request).decoded_email_verify_token = decodedEmailVerifyToken

              return true
            } catch (error) {
              // Lỗi truyền refresh token sai định dạng trả về bởi verifyToken
              if (error instanceof JsonWebTokenError) {
                throw new ErrorWithStatus({
                  message: capitalize(error.message),
                  status: HttpStatusCode.Unauthorized
                })
              }
              throw error
            }
          }
        }
      }
    },
    ['body']
  )
)

export const forgotPasswordValidator = validate(
  checkSchema(
    {
      email: {
        notEmpty: { bail: true, errorMessage: UsersMessages.EmailIsRequired },
        isEmail: { bail: true, errorMessage: UsersMessages.EmailIsInvalid },
        custom: {
          options: async (value, { req }) => {
            const user = await userService.checkEmailExist(value)

            if (user == null) {
              throw new ErrorWithStatus({
                message: UsersMessages.UserNotFound,
                status: HttpStatusCode.NotFound
              })
            }

            // set user info vào request
            req.user = user
            return true
          }
        },
        trim: true
      }
    },
    ['body']
  )
)

export const verifyForgotPasswordTokenValidator = validate(
  checkSchema(
    {
      forgot_password_token: forgotPasswordTokenSchema
    },
    ['body']
  )
)

export const resetPasswordValidator = validate(
  checkSchema(
    {
      forgot_password_token: forgotPasswordTokenSchema,
      password: passwordSchema,
      confirm_password: confirmPasswordSchema
    },

    ['body']
  )
)

export const verifyUserValidator = (req: Request, res: Response, next: NextFunction) => {
  const { verify } = req.decoded_authorization as TokenPayload

  if (verify !== UserVerifyStatus.Verified) {
    return next(new ErrorWithStatus({ message: UsersMessages.UserNotVerified, status: HttpStatusCode.Forbidden }))
  }
  next()
}

export const updateMeValidator = validate(
  checkSchema(
    {
      name: {
        ...nameSchema,
        optional: true
      },
      date_of_birth: {
        ...dateOfBirthSchema,
        optional: true
      },
      bio: {
        optional: true,
        isString: {
          errorMessage: UsersMessages.BioMustBeAString
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: UsersMessages.BioLengthRequired
        }
      },
      location: {
        optional: true,
        isString: {
          errorMessage: UsersMessages.LocationMustBeAString
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: UsersMessages.LocationLengthRequired
        }
      },
      website: {
        optional: true,
        isString: {
          errorMessage: UsersMessages.WebsiteMustBeAString
        },
        trim: true,
        isLength: {
          options: {
            min: 1,
            max: 200
          },
          errorMessage: UsersMessages.WebsiteLengthRequired
        }
      },
      username: {
        optional: true,
        isString: {
          errorMessage: UsersMessages.UsernameMustBeAString
        },
        trim: true,
        custom: {
          options: async (value: string) => {
            if (!REGEX_USERNAME.test(value)) {
              throw new Error(UsersMessages.UsernameInvalid)
            }

            const user = await databaseService.users.findOne({ username: value })

            // Check username phía user update có trùng với user khác trong DB
            if (user) {
              throw new Error(UsersMessages.UsernameAlreadyExists)
            }
            return true
          }
        }
      },
      avatar: imageSchema,
      cover_photo: imageSchema
    },
    ['body']
  )
)

export const followValidator = validate(
  checkSchema(
    {
      followed_user_id: userIdSchema
    },
    ['body']
  )
)

export const unfollowValidator = validate(
  checkSchema(
    {
      user_id: userIdSchema
    },
    ['params']
  )
)

export const changePasswordValidator = validate(
  checkSchema(
    {
      old_password: {
        notEmpty: { bail: true, errorMessage: UsersMessages.PasswordIsRequired },
        custom: {
          options: async (value: string, { req }) => {
            const { user_id } = (req as Request).decoded_authorization as TokenPayload

            const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })

            if (!user) {
              throw new ErrorWithStatus({
                message: UsersMessages.UserNotFound,
                status: HttpStatusCode.NotFound
              })
            }

            // Kiểm tra và so sánh old password truyền lên từ req vs trong DB có trùng khớp không
            const { password } = user
            const isMatch = password === hashPassword(value)

            if (!isMatch) {
              throw new ErrorWithStatus({
                message: UsersMessages.PasswordIsIncorrect,
                status: HttpStatusCode.Unauthorized
              })
            }

            // New password không được giống old password
            if (password === hashPassword((req.body as ChangePasswordReqBody).password)) {
              throw new Error(UsersMessages.OldPasswordAndNewPasswordMustBeDifferent)
            }

            return true
          }
        }
      },
      password: passwordSchema,
      confirm_password: confirmPasswordSchema
    },
    ['body']
  )
)

export const isUserLoggedInValidator = (middleware: (req: Request, res: Response, next: NextFunction) => void) => {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.headers.authorization) {
      return middleware(req, res, next)
    }

    next()
  }
}

export const getConversationsValidator = validate(
  checkSchema(
    {
      receiver_id: userIdSchema
    },
    ['params']
  )
)
