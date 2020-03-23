import { Module } from '@nestjs/common';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from "@nestjs/mongoose";

import { configModule } from './configure.root'
import { TokenModule } from './token/token.module';
import { MailModule } from './mail/mail.module';
import { CatsController } from './cats/cats.controller';



@Module({
    imports: [
        UserModule,
        AuthModule,
        configModule,
        MongooseModule.forRoot(
            process.env.MONGODB_WRITE_CONNECTION_STRING,
            {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                useCreateIndex: true,
            }
        ),
        TokenModule,
        MailModule
    ],
    controllers: [CatsController],
})
export class AppModule {
}
