import express from 'express'
import cors, { CorsOptions } from 'cors'
import helmet from 'helmet'
import fs from 'fs'
import path from 'path'
import { createServer } from 'http'
import databaseService from './services/database.services'
import { defaultErrorHandler } from './middlewares/error.middlewares'
import usersRouter from './routes/users.routes'
import mediasRouter from './routes/medias.routes'
import { initFolder } from './utils/file'
import { UPLOAD_VIDEO_DIR } from './constants/dir'
import staticRouter from './routes/static.routes'
import tweetsRouter from './routes/tweets.routes'
import bookmarksRouter from './routes/bookmarks.routes'
import likesRouter from './routes/likes.routes'
import searchRouter from './routes/search.routes'
import './utils/s3'
import conversationsRouter from './routes/conversations.routes'
import { initSocket } from './utils/socket'
import swaggerUi from 'swagger-ui-express'
import YAML from 'yaml'
import { envConfig, isProduction } from './constants/config'
import { rateLimit } from 'express-rate-limit'

const file = fs.readFileSync(path.resolve('src/openapi/twitter-swagger.yaml'), 'utf8')
const swaggerDocument = YAML.parse(file)

databaseService.connect().then(() => {
  databaseService.indexUsers()
  databaseService.indexRefreshTokens()
  databaseService.indexFollowers()
  databaseService.indexHashtags()
  databaseService.indexBookmarks()
  databaseService.indexLikes()
  databaseService.indexTweets()
})
// Khởi tạo ứng dụng Express
const app = express()
const httpServer = createServer(app)

const corsOptions: CorsOptions = {
  origin: isProduction ? envConfig.clientUrl : '*'
}
app.use(cors(corsOptions))
app.use(helmet())

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
  standardHeaders: 'draft-7', // draft-6: `RateLimit-*` headers; draft-7: combined `RateLimit` header
  legacyHeaders: false // Disable the `X-RateLimit-*` headers.
  // store: ... , // Use an external store for consistency across multiple server instances.
})
app.use(limiter)

const port = envConfig.port

// Khởi tạo upload folder
initFolder()

// Sử dụng middleware để parse dữ liệu (`JSON` hoặc `URL-encoded forms`) từ body của POST request
app.use(express.urlencoded({ extended: false }))
app.use(express.json())

app.get('/ping', (_req, res) => {
  res.send('pong')
})

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument))

app.use('/users', usersRouter)
// Medias route
app.use('/medias', mediasRouter)
// Tweets route
app.use('/tweets', tweetsRouter)
// Bookmarks route
app.use('/bookmarks', bookmarksRouter)
// Likes route
app.use('/likes', likesRouter)
// Search route
app.use('/search', searchRouter)
// Conversations route
app.use('/conversations', conversationsRouter)

// Serving static files
app.use('/static', staticRouter)
app.use('/static/video', express.static(UPLOAD_VIDEO_DIR))

// Khi app xuất hiện lỗi sẽ được xử lý lỗi tại Error handler này
app.use(defaultErrorHandler)
// init Socket Server
initSocket(httpServer)

httpServer.listen(port, () => {
  console.log(`Server is running on port ${port}`)
})
