require("dotenv/config");
const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const { verify } = require("jsonwebtoken");
const { hash, compare } = require("bcryptjs");

// import our own module
const {
  createAccessToken,
  createRefreshToken,
  sendAccessToken,
  sendRefreshToken,
} = require("./token");

const { isAuth } = require("./isAuth");
const { fakeDB } = require("./fakeDB");

// install server
const server = express();

// use express middleware for easier cookie handling
server.use(cookieParser());

server.use(cors({ origin: "http://localhost:3000", credentials: true }));

// needed to be able to read body data
server.use(express.json()); // to support JSON-encoded bodies
server.use(express.urlencoded({ extended: true })); // support URL-encoded bodies

//////////////////////////////////// here is our route
// 1. Register a user
server.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Check if user exist
    const user = fakeDB.find((user) => user.email === email);
    if (user) throw new Error("User already exist");

    // 2. If not user ExtensionScriptApis, hash password
    const hashedPassword = await hash(password, 10);

    // 3. Insert the user in 'database'
    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashedPassword,
    });

    // console.log(fakeDB);
    res.send({ message: "User created" });
  } catch (err) {
    res.send({ error: `${err.message}` });
  }
});

// 2. login user
server.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // 1. Find user in "database". If not exist send error
    const user = fakeDB.find((user) => user.email === email);
    if (!user) throw new Error("User does not exist");

    // 2. Compare crypted password and see if checks outerHeight. Send error if not
    const valid = await compare(password, user.password);
    if (!valid) throw new Error("Password not correct");

    // 3. Create refresh and access token
    const accesstoken = createAccessToken(user.id);
    const refreshtoken = createRefreshToken(user.id); // Note: We can have multiple refresh token version

    // 4. Put the refreshtoken in the database
    user.refreshtoken = refreshtoken;
    console.log(fakeDB);

    // 5. Send token. Refreshtoken as a cookie and accesstoken as a regular response
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(req, res, accesstoken);
  } catch (err) {
    res.send({ Error: err.message });
  }
});

// 3. Logout a user
server.post("/logout", (req, res) => {
  res.clearCookie("refreshToken", { path: "/refresh_token" });
  return res.send({
    message: "Logged out",
  });
});

// 4. Protected route
server.post("/protected", async (req, res) => {
  try {
    const userId = isAuth(req);
    if (userId !== null) {
      res.send({
        data: "This is protected data.",
        user: fakeDB.find((user) => user.id === userId),
      });
    }
  } catch (err) {
    res.send({ Error: err.message });
  }
});

// 5. Get a new access token with a refresh token
server.post("/refresh_token", (req, res) => {
  const token = req.cookies.refreshToken; // we can do this because we have install cookie-parser

  // If we don't have a token in our request
  if (!token) return res.send({ accesstoken: "" });
  // We have a token, let's verify it!
  let payload = null;
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (err) {
    console.log({ accesstoken: "" });
  }
  // Token is valid, check if user exist
  const user = fakeDB.find((user) => user.id === payload.userId);
  if (!user) return res.send({ accesstoken: "" });

  // User exist, Check if refreshtoken exist on user
  if (user.refreshtoken !== token) {
    return res.send({ accesstoken: "" });
  }

  // Token exist, create new Refresh and Access Token
  const accesstoken = createAccessToken(user.id);
  const refreshtoken = createRefreshToken(user.id);
  user.refreshtoken = refreshtoken;

  // All good to go. Send new refreshtoken and accesstoken
  sendRefreshToken(res, refreshtoken);
  return res.send({ accesstoken });
});

// /////////////////////////////// launch app
// launch our app
server.listen(process.env.PORT, () => {
  console.log(`listen on port : ${process.env.PORT}`);
});
