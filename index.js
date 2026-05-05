import express from "express";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import cors from "cors";
import Testdb from "./DB/Testdb.js";
import bcrypt, { compare } from "bcryptjs";
import { createAccess, createRefresh,sendaccestoken, sendrefreshtoken } from "./token.js";
import { isAuth } from "./isAuth.js";
import jwt from "jsonwebtoken";


dotenv.config();

const index = express();

index.use(cors({
    origin: "https://auth-frontend-gamma-taupe.vercel.app/",
    credentials: true,
}));

index.use(cookieParser());
index.use(express.json());
index.use(express.urlencoded({ extended: true }));

// Register
index.post("/register", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = Testdb.find(user => user.email === email);
        if (user) return res.status(400).json({ message: "User exists" });

        const hashedPassword = await bcrypt.hash(password, 10);
        console.log(hashedPassword);
        Testdb.push({
            id: Testdb.length,
            email,
            password: hashedPassword
        });

        res.status(200).json({ message: "User created successfully" });

    } catch (error) {
        res.status(500).json({ error });
    }
});

// Login
index.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = Testdb.find(user => user.email === email);
        if (!user) return res.status(400).json({ message: "User not found" });

        const valid = await compare(password, user.password);
        if (!valid) return res.status(400).json({ message: "Incorrect password" });

        const ACCESS_token = createAccess(user.id);
        const REFRESH_token = createRefresh(user.id);

        user.REFRESH_token = REFRESH_token;
        console.log(Testdb);

        sendrefreshtoken(res,REFRESH_token);
        sendaccestoken(res,req,ACCESS_token);

            } catch (error) {
        res.status(500).json({ error });
    }
});

    //logout user
    index.post("/logout",(_req,res)=>{
        res.clearCookie("REFRESH_token",{path:'/refreshtoken'});
        return res.send({
            Message:"Logged out",
        })
    });

    //protected route
    index.post("/protected",(req,res)=>{
        try {
            const userid = isAuth(req);
            if(userid !== null){
                res.send({
                    data:"This is protected"
                });
            };
        } catch (error) {
            res.status(500).json({ error });
        };
    });

    //access refresh token
    index.post("/refreshtoken", async (req, res) => {
    const token = req.cookies.REFRESH_token;

    if (!token) return res.send({ ACCESS_token: "" });

    let payload = null;

    try {
        payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
    } catch (error) {
        return res.send({ ACCESS_token: "" });
    }

    const user = Testdb.find(user => user.id === payload.userid);

    if (!user) return res.send({ ACCESS_token: "" });

    if (user.REFRESH_token !== token) {
        return res.send({ ACCESS_token: "" });
    }

    const ACCESS_token = createAccess(user.id);
    const REFRESH_token = createRefresh(user.id);

    user.REFRESH_token = REFRESH_token;

    sendrefreshtoken(res, REFRESH_token);

    return res.send({ ACCESS_token });
});



index.listen(4000, () => {
    console.log("Server running on port 4000");
});


//"ACCESS_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOjAsImlhdCI6MTc3Nzk1NzMyMCwiZXhwIjoxNzc3OTU4MjIwfQ.A5wRbm_n3X6mejaBHOiog8xTwg6lUE-onv_XQakByjM"
// $2b$10$b32Nls7aLKzjACyhEvP88O80aWBT6xois85St90/RIZZoYT0dqQH6