export enum UserVerifyStatus {
  Unverified, // chưa xác thực email, mặc định = 0
  Verified, // đã xác thực email
  Banned // bị khóa
}

export enum TokenType {
  AccessToken = 'access_token',
  RefreshToken = 'refresh_token',
  ForgotPasswordToken = 'forgot_password_token',
  EmailVerifyToken = 'email_verify_token'
}

export enum MediaType {
  Image = 'image',
  Video = 'video'
}

export enum TweetAudience {
  Everyone, // 0
  TwitterCircle // 1
}

export enum TweetType {
  Tweet,
  Retweet,
  Comment,
  QuoteTweet
}

export enum HttpStatusCode {
  Continue = 100,
  SwitchingProtocols = 101,
  Processing = 102,
  EarlyHints = 103,
  Ok = 200,
  Created = 201,
  Accepted = 202,
  NonAuthoritativeInformation = 203,
  NoContent = 204,
  ResetContent = 205,
  PartialContent = 206,
  MultiStatus = 207,
  AlreadyReported = 208,
  ImUsed = 226,
  MultipleChoices = 300,
  MovedPermanently = 301,
  Found = 302,
  SeeOther = 303,
  NotModified = 304,
  UseProxy = 305,
  Unused = 306,
  TemporaryRedirect = 307,
  PermanentRedirect = 308,
  BadRequest = 400,
  Unauthorized = 401,
  PaymentRequired = 402,
  Forbidden = 403,
  NotFound = 404,
  MethodNotAllowed = 405,
  NotAcceptable = 406,
  ProxyAuthenticationRequired = 407,
  RequestTimeout = 408,
  Conflict = 409,
  Gone = 410,
  LengthRequired = 411,
  PreconditionFailed = 412,
  PayloadTooLarge = 413,
  UriTooLong = 414,
  UnsupportedMediaType = 415,
  RangeNotSatisfiable = 416,
  ExpectationFailed = 417,
  ImATeapot = 418,
  MisdirectedRequest = 421,
  UnprocessableEntity = 422,
  Locked = 423,
  FailedDependency = 424,
  TooEarly = 425,
  UpgradeRequired = 426,
  PreconditionRequired = 428,
  TooManyRequests = 429,
  RequestHeaderFieldsTooLarge = 431,
  UnavailableForLegalReasons = 451,
  InternalServerError = 500,
  NotImplemented = 501,
  BadGateway = 502,
  ServiceUnavailable = 503,
  GatewayTimeout = 504,
  HttpVersionNotSupported = 505,
  VariantAlsoNegotiates = 506,
  InsufficientStorage = 507,
  LoopDetected = 508,
  NotExtended = 510,
  NetworkAuthenticationRequired = 511
}

export enum UsersMessages {
  ValidationError = 'Validation Error',
  EmailOrPasswordIsIncorrect = 'Email or password is incorrect',
  NameIsRequired = 'Name is required',
  NameMustBeAString = 'Name must be a string',
  NameLengthRequired = 'Name length must be from 1 to 100 characters',
  EmailAlreadyExists = 'Email already exists',
  EmailIsRequired = 'Email is required',
  EmailIsInvalid = 'Email is invalid',
  PasswordIsRequired = 'Password is required',
  PasswordMustBeAString = 'Password must be a string',
  PasswordLengthRequired = 'Password length must be from 6 to 50 characters',
  PasswordMustBeStrong = 'Password must be at least 6 characters long and contain at least 1 lowercase letter, 1 uppercase letter, 1 number and 1 symbols',
  ConfirmPasswordIsRequired = 'Confirm password is required',
  ConfirmPasswordMustBeAString = 'Confirm password must be a string',
  PasswordsDoNotMatch = 'Passwords do not match',
  PasswordIsIncorrect = 'Password is incorrect',
  OldPasswordAndNewPasswordMustBeDifferent = 'Old password and new password must be different',
  ChangePasswordSuccess = 'Change password successfully',
  DateOfBirthMustBeISO8601 = 'Date of birth must be ISO 8601',
  LoginSuccess = 'Login success',
  RegisterSuccess = 'Register success',
  LogoutSuccess = 'Logout success',
  AccessTokenIsRequired = 'Access token is required',
  AccessTokenIsInvalid = 'Access token is invalid',
  RefreshTokenIsRequired = 'Refresh token is required',
  RefreshTokenIsInvalid = 'Refresh token is invalid',
  UsedRefreshTokenOrNotExist = 'Used refresh token or not exist',
  RefreshTokenSuccess = 'Refresh token successfully',
  EmailVerifyTokenIsRequired = 'Email verify token is required',
  UserNotFound = 'User not found',
  EmailAlreadyVerifiedBefore = 'Email already verified before',
  EmailVerifySuccess = 'Email verify success',
  ResendVerificationEmailSuccess = 'Resend verification email success',
  CheckEmailToResetPassword = 'Check email to reset password',
  ForgotPasswordTokenIsRequired = 'Forgot password token is required',
  VerifyForgotPasswordSuccess = 'Verify forgot password successfully',
  ForgotPasswordTokenIsInvalid = 'Forgot password token is invalid',
  ResetPasswordSuccess = 'Reset password successfully',
  GetMeSuccess = 'Get my profile successfully',
  GetProfileSuccess = 'Get profile successfully',
  UpdateMeSuccess = 'Update my profile successfully',
  UserNotVerified = 'User not verified',
  BioMustBeAString = 'Bio must be a string',
  BioLengthRequired = 'Bio length must be from 1 to 200 characters',
  LocationMustBeAString = 'Location must be a string',
  LocationLengthRequired = 'Location length must be from 1 to 200 characters',
  WebsiteMustBeAString = 'Website must be a string',
  WebsiteLengthRequired = 'Website length must be from 1 to 200 characters',
  UsernameMustBeAString = 'Username must be a string',
  UsernameLengthRequired = 'Username length must be from 1 to 50 characters',
  UsernameInvalid = 'Username length must be 4-15 characters and contains only letters, numbers, underscores and not only numbers',
  UsernameAlreadyExists = 'Username already exists',
  ImageURLMustBeAString = 'Image URL must be a string',
  ImageURLLengthRequired = 'Image URL length must be from 1 to 400 characters',
  FollowSuccess = 'Follow successfully',
  UnfollowSuccess = 'Unfollow successfully',
  InvalidUserId = 'Invalid user id',
  AlreadyFollowed = 'Already followed',
  AlreadyUnfollowed = 'Already unfollowed',
  CannotFollowYourself = 'Cannot follow yourself',
  GoogleEmailNotVerified = 'Google email not verified'
}

export enum MediasMessages {
  'UploadImageSuccess' = 'Uploading image successfully',
  'UploadVideoSuccess' = 'Uploading video successfully',
  'FileTypeIsNoValid' = 'File type is not valid',
  'FileIsEmpty' = 'File is empty'
}
