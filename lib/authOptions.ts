import { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { connectionToDatabase } from "@/lib/db";
import bcrypt from "bcryptjs";
import User from "@/models/User";

export const authOptions : NextAuthOptions ={
    providers:[
        CredentialsProvider({
            name: "Credentials",
            credentials: {
                email: { label: "Email", type: "text" },   
                password: { label: "Password", type: "password" }
              },
              async authorize(credentials){
                if(!credentials || !credentials.email || !credentials.password){
                    throw new Error('Email or password is missing');
                }

                try{
                    await connectionToDatabase();
                    const user=await User.findOne({email:credentials.email});
                    if(!user){
                        throw new Error('User not found');
                    }

                    const isValid=await bcrypt.compare(credentials.password,user.password);
                    if(!isValid){
                        throw new Error('Invalid password');
                    }

                    return user;
                }catch(error){
                    throw new Error('Invalid email or password');
                }

              }
        })
    ],
    callbacks:{
        async jwt({token,user}){
            if(user){
                token.id=user.id;
            }
            return token;
        },
        async session({session,token}){
                if(session.user){
                    session.user.id=token.id as string;
}

            return session;
    }
    },
    pages:{
        signIn:"/login",
        error:"/error",
    },
    session:{
        strategy:"jwt",
        maxAge: 30*24*60*60
    },
    secret:process.env.NEXTAUTH_SECRET
}