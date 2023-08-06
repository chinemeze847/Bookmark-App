import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from "argon2"
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";

@Injectable({})
export class AuthService{
    constructor(private prisma : PrismaService){
    }

    async signin(dto: AuthDto){

        //find the user
        const user = await this.prisma.user.findUnique({
            where : {
                email : dto.email
            }
        })
        //if user not found

        if(!user){
            throw new ForbiddenException("Credentials incorrect")
        }

        //compare password
        const matches = await argon.verify(
            user.hash, 
            dto.password
        )

        //guard
        if(!matches){
            throw new ForbiddenException("Credentials incorrect")
        }

        delete user.hash;

        return user;
    }

    async signup(dto: AuthDto){

        //hash the password
        const hash = await argon.hash(dto.password);

        //save in db
        try{
            const user = await this.prisma.user.create({
                data : {
                    email : dto.email,
                    hash
                }
            })
            delete user.hash;
            //return the user
            return user;
        }catch(error){
            if(error instanceof PrismaClientKnownRequestError)
            {
                if(error.code === 'P2002')
                {
                    throw new ForbiddenException('credentials taken')
                }
                throw error
            }
        }
    }
}