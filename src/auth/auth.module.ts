import { Module } from '@nestjs/common';
import { JwtModule } from "@nestjs/jwt";

import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import {JwtStrategy } from './jwt.strategy'
import { configModule } from "../configure.root";
import { PassportModule } from "@nestjs/passport";

import { UserModule } from "../user/user.module";
import { TokenModule } from "../token/token.module";




import { MailModule } from '../mail/mail.module';
import { UserService } from "../user/user.service";

@Module({
  imports: [
      UserModule,
      TokenModule,
      configModule,
      PassportModule.register({defaultStrategy: 'jwt'}),
      JwtModule.register({
        secret: process.env.JWT_SECRET,
        signOptions: { expiresIn: '1d' }
      }),
      MailModule
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController]
})
export class AuthModule {}
