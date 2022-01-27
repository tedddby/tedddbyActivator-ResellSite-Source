const express = require("express");

const hbs = require("hbs");

const bodyParser = require("body-parser");

const cookieParser = require("cookie-parser");

const path = require("path");

const public = path.join(__dirname, "public");

const handler = require("./routers/handler.js");

const port = 3050;

const app = express();

app.set("trust proxy", true);

app.set("view engine", "hbs");

app.use(express.static(public));

app.use(cookieParser());

app.use(bodyParser.urlencoded({extended:true}));

app.use(bodyParser.json());

app.use("/", handler);

app.listen(port, (error) => { if(error) console.log(error); else console.log(`App running on ${port}`) })