const express = require('express')
const morgan = require('morgan')
const dotenv = require('dotenv')
const cookieParser = require('cookie-parser')
const app = express()

// Middlewares
dotenv.config({ path: './config/config.env' })
require('./config/db') // database
app.use(express.json()) //bodyparser
app.use(cookieParser()) // Cookie Parser
if(process.env.NODE_ENV === 'development'){ // production
    app.use(morgan('dev'))
}

// ROUTES
app.use('/api/v1/auth', require('./routes/auth'))



const PORT = process.env.PORT || 3000
const server = app.listen(PORT, console.log(`Server is running in ${process.env.NODE_ENV} mode on port ${PORT}`))


// HANDLE UNHDNDLEC PROMISE 
process.on("unhandledRejection", (error, promise) => {
    console.log(`ERROR: ${error}`)
    // close the server and finish the process
    server.close(() => process.exit(1))
})