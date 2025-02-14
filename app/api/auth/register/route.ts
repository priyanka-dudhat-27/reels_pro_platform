import { NextResponse,NextRequest } from "next/server";
import { connectionToDatabase } from "@/lib/db";
import User from "@/models/User";

export async function POST(request:NextRequest){
try{
    const {email,password}=await request.json();

    if(!email || !password){
        return NextResponse.json(
            {error:'Email or password is missing'},
            {status:400}
        );
    }

    await connectionToDatabase();

    const existingUser=await User.findOne({email});
    if(existingUser){
        return NextResponse.json(
            {error:'Email already registered'},
            {status:400}
        );

    }
    await User.create({email,password});

    return NextResponse.json(
        {message:'User registered successfully'},
        {status:201}
    );
}   catch(error){
    return NextResponse.json(
        {error:"Failed to register User"},
        {status:500}
    );
} 
}
