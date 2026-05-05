import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";

const createAccess = (userid) => {
    return jwt.sign({ userid }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "15m",
    });
};

const createRefresh = (userid) => {
    return jwt.sign({ userid }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "7d",
    });
};

const sendaccestoken = (res,req,ACCESS_token)=>{
    res.send({
        ACCESS_token,
        email:req.body.email,
    });
};

const sendrefreshtoken = (res,REFRESH_token)=>{
    res.cookie('REFRESH_token',REFRESH_token,{
        httpOnly:true,
        path:'/refreshtoken',
    })
};

export { createAccess, createRefresh, sendaccestoken, sendrefreshtoken };