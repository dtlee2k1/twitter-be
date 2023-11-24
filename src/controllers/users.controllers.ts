import { Request, Response } from 'express'
import { ParamsDictionary } from 'express-serve-static-core'
import { ObjectId } from 'mongodb'
import { HttpStatusCode, UserVerifyStatus, UsersMessages } from '~/constants/enums'
import {
  LoginReqBody,
  TokenPayload,
  RegisterReqBody,
  LogoutReqBody,
  VerifyEmailReqBody,
  VerifyForgotPasswordReqBody,
  ForgotPasswordReqBody,
  ResetPasswordReqBody,
  UpdateMeReqBody
} from '~/models/requests/User.requests'
import User from '~/models/schemas/User.schema'
import databaseService from '~/services/database.services'
import userService from '~/services/users.services'

// Chứa các file nhận request, gọi đến service để xử lý logic nghiệp vụ, trả về response

export const loginController = async (req: Request<ParamsDictionary, any, LoginReqBody>, res: Response) => {
  // Thực hiện xử lý với dữ liệu
  // Destructuring lấy ra user được set trong req ở middlewares
  const { _id: user_id, verify } = req.user as User

  const result = await userService.login({ user_id: (user_id as ObjectId).toString(), verify })
  // Trả về phản hồi cho client
  res.json({
    message: UsersMessages.LoginSuccess,
    result
  })
}

export const registerController = async (req: Request<ParamsDictionary, any, RegisterReqBody>, res: Response) => {
  // Thực hiện xử lý với dữ liệu
  const result = await userService.register(req.body)
  // Trả về phản hồi cho client
  res.json({
    message: UsersMessages.RegisterSuccess,
    result
  })
}

export const logoutController = async (req: Request<ParamsDictionary, any, LogoutReqBody>, res: Response) => {
  // Trả về phản hồi cho client
  res.json({
    message: UsersMessages.LogoutSuccess
  })
}

export const verifyEmailController = async (req: Request<ParamsDictionary, any, VerifyEmailReqBody>, res: Response) => {
  // Thực hiện xử lý với dữ liệu
  // Destructuring lấy ra user_id được set trong req ở middlewares
  const { user_id } = req.decoded_email_verify_token as TokenPayload

  const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })

  if (!user) {
    return res.status(HttpStatusCode.NotFound).json({
      message: UsersMessages.UserNotFound
    })
  }

  // Đã verified token thành công trước đó thì nó sẽ set lại thành chuỗi rỗng
  if (user.email_verify_token === '') {
    return res.json({
      message: UsersMessages.EmailAlreadyVerifiedBefore
    })
  }

  const result = await userService.verifyEmail(user_id)

  // Trả về phản hồi cho client
  res.json({
    message: UsersMessages.EmailVerifySuccess,
    result
  })
}

export const resendVerifyEmailController = async (req: Request, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload

  const user = await databaseService.users.findOne({ _id: new ObjectId(user_id) })

  if (!user) {
    return res.status(HttpStatusCode.NotFound).json({
      message: UsersMessages.UserNotFound
    })
  }

  if (user.verify === UserVerifyStatus.Verified) {
    return res.status(HttpStatusCode.NotFound).json({
      message: UsersMessages.EmailAlreadyVerifiedBefore
    })
  }

  const result = await userService.resendVerifyEmail(user_id)

  res.json(result)
}

export const forgotPasswordController = async (
  req: Request<ParamsDictionary, any, ForgotPasswordReqBody>,
  res: Response
) => {
  const { _id, verify } = req.user as User

  const result = await userService.forgotPassword({ user_id: (_id as ObjectId).toString(), verify })

  res.json(result)
}

export const verifyForgotPasswordController = async (
  req: Request<ParamsDictionary, any, VerifyForgotPasswordReqBody>,
  res: Response
) => {
  // Trả về phản hồi cho client
  res.json({
    message: UsersMessages.VerifyForgotPasswordSuccess
  })
}

export const resetPasswordController = async (
  req: Request<ParamsDictionary, any, ResetPasswordReqBody>,
  res: Response
) => {
  // Trả về phản hồi cho client
  const { user_id } = req.decoded_forgot_password_token as TokenPayload
  const { password } = req.body

  const result = await userService.resetPassword(user_id, password)
  res.json(result)
}

export const getMeController = async (req: Request<ParamsDictionary, any, ResetPasswordReqBody>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload

  // Get user profile from database
  const user = await userService.getMe(user_id)

  // Trả về phản hồi cho client
  res.json({
    message: UsersMessages.GetMeSuccess,
    result: user
  })
}

export const updateMeController = async (req: Request<ParamsDictionary, any, UpdateMeReqBody>, res: Response) => {
  const { user_id } = req.decoded_authorization as TokenPayload
  const { body } = req

  const user = await userService.updateMe(user_id, body)
  // Trả về phản hồi cho client
  res.json({
    message: UsersMessages.GetMeSuccess,
    result: user
  })
}
