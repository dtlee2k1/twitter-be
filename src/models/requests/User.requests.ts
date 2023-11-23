import { JwtPayload } from 'jsonwebtoken'
import { TokenType } from '~/constants/enums'

export interface LoginReqBody {
  email: string
  password: string
}

export interface LogoutReqBody {
  refresh_token: string
}

export interface RegisterReqBody {
  username: string
  email: string
  password: string
  confirm_password: string
  date_of_birth: string
}

export interface VerifyEmailReqBody {
  email_verify_token: string
}

export interface ForgotPasswordReqBody {
  email: string
}

export interface VerifyForgotPasswordReqBody {
  forgot_password_token: string
}

export interface ResetPasswordReqBody extends VerifyForgotPasswordReqBody {
  password: string
  confirm_password: string
}

export interface TokenPayload extends JwtPayload {
  user_id: string
  type: TokenType
}
