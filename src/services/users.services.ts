import axios from 'axios'
import User from '~/models/schemas/User.schema'
import databaseService from './database.services'
import { RegisterReqBody, UpdateMeReqBody } from '~/models/requests/User.requests'
import { hashPassword } from '~/utils/crypto'
import { signToken, verifyToken } from '~/utils/jwt'
import { HttpStatusCode, TokenType, UserVerifyStatus } from '~/constants/enums'
import { ObjectId } from 'mongodb'
import RefreshToken from '~/models/schemas/ReFreshToken.schema'
import omit from 'lodash/omit'
import { ErrorWithStatus } from '~/models/Errors'
import Follower from '~/models/schemas/Follower.schema'
import { UsersMessages } from '~/constants/messages'
import { sendForgotPasswordEmail, sendVerifyRegisterEmail } from '~/utils/email'
import { envConfig } from '~/constants/config'

class UserService {
  private signAccessToken({ user_id, verify }: { user_id: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: {
        user_id,
        type: TokenType.AccessToken,
        verify
      },
      privateKey: envConfig.jwtSecretAccessToken,
      options: {
        expiresIn: envConfig.accessTokenExpiresIn
      }
    })
  }

  private signRefreshToken({ user_id, verify, exp }: { user_id: string; verify: UserVerifyStatus; exp?: number }) {
    return exp
      ? signToken({
          payload: {
            user_id,
            type: TokenType.RefreshToken,
            verify,
            exp
          },
          privateKey: envConfig.jwtSecretRefreshToken
        })
      : signToken({
          payload: {
            user_id,
            type: TokenType.RefreshToken,
            verify
          },
          privateKey: envConfig.jwtSecretRefreshToken,
          options: {
            expiresIn: envConfig.refreshTokenExpiresIn
          }
        })
  }

  private signEmailVerifyToken({ user_id, verify }: { user_id: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: {
        user_id,
        type: TokenType.EmailVerifyToken,
        verify
      },
      privateKey: envConfig.jwtSecretEmailVerifyToken,
      options: {
        expiresIn: envConfig.emailVerifyTokenExpiresIn
      }
    })
  }

  private signForgotPasswordToken({ user_id, verify }: { user_id: string; verify: UserVerifyStatus }) {
    return signToken({
      payload: {
        user_id,
        type: TokenType.ForgotPasswordToken,
        verify
      },
      privateKey: envConfig.jwtSecretForgotPasswordToken,
      options: {
        expiresIn: envConfig.forgotPasswordTokenExpiresIn
      }
    })
  }

  private async signAccessAndRefreshToken({
    user_id,
    verify,
    exp
  }: {
    user_id: string
    verify: UserVerifyStatus
    exp?: number
  }) {
    return Promise.all([this.signAccessToken({ user_id, verify }), this.signRefreshToken({ user_id, verify, exp })])
  }

  private decodedRefreshToken = (refresh_token: string) => {
    return verifyToken({ token: refresh_token, secretOrPublicKey: envConfig.jwtSecretRefreshToken as string })
  }

  /**
   * Hàm này thực hiện gửi yêu cầu lấy Google OAuth token dựa trên authorization code nhận được từ client-side.
   * @param {string} code - Authorization code được gửi từ client-side.
   * @returns {Object} - Đối tượng chứa Google OAuth token.
   */
  private async getOauthGoogleToken(code: string) {
    const body = {
      code,
      client_id: envConfig.googleClientId,
      client_secret: envConfig.googleClientSecret,
      redirect_uri: envConfig.googleAuthorizedRedirectUri,
      grant_type: 'authorization_code'
    }
    const { data } = await axios.post('https://oauth2.googleapis.com/token', body, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    })
    return data as { access_token: string; id_token: string }
  }

  /**
   * Hàm này thực hiện gửi yêu cầu lấy thông tin người dùng từ Google dựa trên Google OAuth token.
   * @param {Object} tokens - Đối tượng chứa Google OAuth token.
   * @param {string} tokens.id_token - ID token được lấy từ Google OAuth.
   * @param {string} tokens.access_token - Access token được lấy từ Google OAuth.
   * @returns {Object} - Đối tượng chứa thông tin người dùng từ Google.
   */
  private async getGoogleUserInfo({ id_token, access_token }: { id_token: string; access_token: string }) {
    const { data } = await axios.get('https://www.googleapis.com/oauth2/v1/userinfo', {
      params: {
        access_token,
        alt: 'json'
      },
      headers: {
        Authorization: `Bearer ${id_token}`
      }
    })
    return data as {
      id: string
      email: string
      verified_email: boolean
      name: string
      given_name: string
      family_name: string
      picture: string
      locale: string
    }
  }

  async register(payload: RegisterReqBody) {
    const user_id = new ObjectId()

    const email_verify_token = await this.signEmailVerifyToken({
      user_id: user_id.toString(),
      verify: UserVerifyStatus.Unverified
    })
    await databaseService.users.insertOne(
      new User({
        ...payload,
        _id: user_id,
        username: `user_${user_id.toString()}`,
        email_verify_token,
        date_of_birth: new Date(payload.date_of_birth),
        password: hashPassword(payload.password)
      })
    )

    const [access_token, refresh_token] = await this.signAccessAndRefreshToken({
      user_id: user_id.toString(),
      verify: UserVerifyStatus.Unverified
    })

    const { iat, exp } = await this.decodedRefreshToken(refresh_token)

    await databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token, iat, exp })
    )

    // Flow verify Email
    // 1. Server send email to server
    // 2. User click link in email
    // 3. Client send email to server with email_verify_token
    // 4. Server verify email_verify_token
    // 5. Client receive access_token and refresh_token
    await sendVerifyRegisterEmail(payload.email, email_verify_token)

    return {
      access_token,
      refresh_token
    }
  }

  async oauth(code: string) {
    // Gửi authorization code để lấy Google OAuth
    const data = await this.getOauthGoogleToken(code)

    // Lấy ID token và access token từ kết quả trả về
    const { id_token, access_token } = data

    // Gửi Google OAuth token để lấy thông tin người dùng từ Google
    const userInfo = await this.getGoogleUserInfo({ id_token, access_token })

    // Kiểm tra email đã được xác minh từ Google
    if (!userInfo.verified_email) {
      throw new ErrorWithStatus({
        message: UsersMessages.GoogleEmailNotVerified,
        status: HttpStatusCode.Forbidden
      })
    }

    const user = await this.checkEmailExist(userInfo.email)

    if (user) {
      const [access_token, refresh_token] = await this.signAccessAndRefreshToken({
        user_id: user._id.toString(),
        verify: user.verify
      })

      const { iat, exp } = await this.decodedRefreshToken(refresh_token)

      await databaseService.refreshTokens.insertOne(
        new RefreshToken({ user_id: new ObjectId(user._id), token: refresh_token, iat, exp })
      )

      return {
        access_token,
        refresh_token,
        new_user: 0,
        verify: user.verify
      }
    } else {
      const password = (Math.random() + 1).toString(36).substring(2)
      const { access_token, refresh_token } = await this.register({
        email: userInfo.email,
        name: userInfo.name,
        password,
        confirm_password: password,
        date_of_birth: new Date().toISOString()
      })

      return { access_token, refresh_token, new_user: 1, verify: UserVerifyStatus.Unverified }
    }
  }

  async login({ user_id, verify }: { user_id: string; verify: UserVerifyStatus }) {
    const [access_token, refresh_token] = await this.signAccessAndRefreshToken({
      user_id: user_id.toString(),
      verify
    })

    const { iat, exp } = await this.decodedRefreshToken(refresh_token)

    await databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token, iat, exp })
    )

    return {
      access_token,
      refresh_token
    }
  }

  async refreshToken({ user_id, verify, exp }: { user_id: string; verify: UserVerifyStatus; exp: number }) {
    const [access_token, refresh_token] = await this.signAccessAndRefreshToken({ user_id, verify, exp })

    const { iat } = await this.decodedRefreshToken(refresh_token)

    await databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token, iat, exp })
    )

    return {
      access_token,
      refresh_token
    }
  }

  async checkEmailExist(email: string) {
    const user = await databaseService.users.findOne({ email })
    return user
  }

  async checkUserExist({ email, password }: { email: string; password: string }) {
    const user = await databaseService.users.findOne({ email, password: hashPassword(password) })
    return user
  }

  async checkAndDeleteRefreshTokenInDB(token: string) {
    return await databaseService.refreshTokens.findOneAndDelete({ token })
  }

  async verifyEmail(user_id: string) {
    const [token] = await Promise.all([
      this.signAccessAndRefreshToken({ user_id, verify: UserVerifyStatus.Verified }),
      databaseService.users.updateOne(
        { _id: new ObjectId(user_id) },
        { $set: { email_verify_token: '', verify: UserVerifyStatus.Verified, updated_at: new Date() } }
      )
    ])

    const [access_token, refresh_token] = token

    const { iat, exp } = await this.decodedRefreshToken(refresh_token)

    await databaseService.refreshTokens.insertOne(
      new RefreshToken({ user_id: new ObjectId(user_id), token: refresh_token, iat, exp })
    )

    return {
      access_token,
      refresh_token
    }
  }

  async resendVerifyEmail(user_id: string, email: string) {
    const email_verify_token = await this.signEmailVerifyToken({ user_id, verify: UserVerifyStatus.Unverified })

    console.log('Resend verify email token: ', email_verify_token)

    await databaseService.users.updateOne(
      { _id: new ObjectId(user_id) },
      {
        $set: { email_verify_token },
        $currentDate: {
          updated_at: true
        }
      }
    )

    await sendVerifyRegisterEmail(email, email_verify_token)

    return {
      message: UsersMessages.ResendVerificationEmailSuccess
    }
  }

  async forgotPassword({ user_id, verify, email }: { user_id: string; verify: UserVerifyStatus; email: string }) {
    const forgot_password_token = await this.signForgotPasswordToken({ user_id, verify })

    await databaseService.users.updateOne(
      { _id: new ObjectId(user_id) },
      { $set: { forgot_password_token, updated_at: new Date() } }
    )

    console.log('Resend forgot password token: ', forgot_password_token)

    sendForgotPasswordEmail(email, forgot_password_token)

    return {
      message: UsersMessages.CheckEmailToResetPassword
    }
  }

  async resetPassword(user_id: string, password: string) {
    await databaseService.users.updateOne(
      { _id: new ObjectId(user_id) },
      { $set: { forgot_password_token: '', password: hashPassword(password), updated_at: new Date() } }
    )
    return {
      message: UsersMessages.ResetPasswordSuccess
    }
  }

  async changePassword(user_id: string, password: string) {
    await databaseService.users.updateOne(
      { _id: new ObjectId(user_id) },
      { $set: { password: hashPassword(password), updated_at: new Date() } }
    )
    return {
      message: UsersMessages.ChangePasswordSuccess
    }
  }

  async getMe(user_id: string) {
    const user = await databaseService.users.findOne(
      { _id: new ObjectId(user_id) },
      { projection: { password: 0, email_verify_token: 0, forgot_password_token: 0 } }
    )

    return user
  }

  async getProfile(username: string) {
    const user = await databaseService.users.findOne(
      { username },
      {
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0,
          verify: 0,
          created_at: 0,
          updated_at: 0
        }
      }
    )

    if (user === null) {
      throw new ErrorWithStatus({
        message: UsersMessages.UserNotFound,
        status: HttpStatusCode.NotFound
      })
    }

    return user
  }

  async updateMe(user_id: string, payload: UpdateMeReqBody) {
    const _payload = payload.date_of_birth
      ? { ...payload, date_of_birth: new Date(payload.date_of_birth) }
      : omit(payload, ['date_of_birth'])

    const user = await databaseService.users.findOneAndUpdate(
      { _id: new ObjectId(user_id) },
      {
        $set: {
          ..._payload
        },
        $currentDate: {
          updated_at: true
        }
      },
      {
        returnDocument: 'after',
        projection: {
          password: 0,
          email_verify_token: 0,
          forgot_password_token: 0
        }
      }
    )

    return user
  }

  async follow(user_id: string, followed_user_id: string) {
    const follower = await databaseService.followers.findOne({
      user_id: new ObjectId(user_id),
      followed_user_id: new ObjectId(followed_user_id)
    })

    if (follower === null) {
      await databaseService.followers.insertOne(
        new Follower({
          user_id: new ObjectId(user_id),
          followed_user_id: new ObjectId(followed_user_id)
        })
      )
      return {
        message: UsersMessages.FollowSuccess
      }
    }

    return {
      message: UsersMessages.AlreadyFollowed
    }
  }

  async unfollow(user_id: string, followed_user_id: string) {
    const follower = await databaseService.followers.findOne({
      user_id: new ObjectId(user_id),
      followed_user_id: new ObjectId(followed_user_id)
    })

    if (follower === null) {
      return {
        message: UsersMessages.AlreadyUnfollowed
      }
    }

    await databaseService.followers.deleteOne({
      user_id: new ObjectId(user_id),
      followed_user_id: new ObjectId(followed_user_id)
    })

    return {
      message: UsersMessages.UnfollowSuccess
    }
  }
}

const userService = new UserService()
export default userService
