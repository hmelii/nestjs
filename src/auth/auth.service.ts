import { Injectable, UnauthorizedException, BadRequestException, MethodNotAllowedException } from '@nestjs/common';
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from '@nestjs/config';
import { SignOptions } from "jsonwebtoken";
import  * as moment from 'moment';
import * as bcrypt from "bcrypt";
import * as _ from "lodash";

import { UserService } from "../user/user.service";
import { TokenService } from "../token/token.service";
import { MailService } from '../mail/mail.service';

import { CreateUserDto } from "../user/dto/create-user.dto";
import { CreateUserTokenDto } from "../token/dto/create-user-token.dto";

import { IUser } from '../user/interfaces/user.interface';

import { roleEnum } from '../user/enums/role.enum';
import { statusEnum } from '../user/enums/status.enum';
import { ITokenPayload } from "../token/interfaces/token-payload.interface";
import { ChangePasswordDto } from "./dto/change-password.dto";
import { userSensitiveFieldsEnum } from "../user/enums/protected-fields.enum";
import { IReadableUser } from "../user/interfaces/readable-user.interface";
import { SignInDto } from "./dto/signin.dto";

@Injectable()
export class AuthService {
    private readonly clientAppUrl: string;

    constructor(
        private readonly jwtService: JwtService,
        private readonly userService: UserService,
        private readonly tokenService: TokenService,
        private readonly configService: ConfigService,
        private readonly mailService: MailService,
    ) {
        this.clientAppUrl = this.configService.get<string>('FE_APP_URL');
    }

    async signUp(createUserDto: CreateUserDto): Promise<boolean> {
        const user = await this.userService.create(createUserDto, [roleEnum.user]);
        await this.sendConfirmation(user);
        return true;
    }

    async signIn(signInDto: SignInDto): Promise<IReadableUser> {
        const { email, password } = signInDto;
        const user = await this.userService.findByEmail(email);

        if (user && (await bcrypt.compare(password, user.password))) {
            if (user.status !== statusEnum.active) {
                throw new MethodNotAllowedException();
            }
            const tokenPayload: ITokenPayload = {
                _id: user._id,
                status: user.status,
                roles: user.roles,
            };
            const token = await this.generateToken(tokenPayload);
            const expiredAt = moment()
                .add(1, 'day')
                .toISOString();

            await this.saveToken({
                token,
                expiredAt,
                uId: user._id,
            });

            const readableUser = user.toObject() as IReadableUser;
            readableUser.accessToken = token;

            return _.omit<any>(readableUser, Object.values(userSensitiveFieldsEnum)) as IReadableUser; // здесь обрезаются лишние поля, чтобы они не попадали на front
        }
        throw new BadRequestException('Invalid credentials');
    }

    async changePassword(changePasswordDto: ChangePasswordDto): Promise<boolean> {
        const password = await this.userService.hashPassword(changePasswordDto.password);

        await this.userService.update(changePasswordDto._id, { password });
        await this.tokenService.deleteAll(changePasswordDto._id);
        return true;
    }


    async confirm(token: string): Promise<IUser> {
        const data = await this.verifyToken(token);
        const user = await this.userService.find(data._id);

        await this.tokenService.delete(data._id, token);

        if (user && user.status === statusEnum.pending) {
            user.status = statusEnum.active;
            return user.save();
        }
        throw new BadRequestException('Confirmation error');
    }

    async sendConfirmation(user: IUser) {
        const expiresIn = 60 * 60 * 24; // 24 hours
        const tokenPayload = {
            _id: user._id,
            status: user.status,
            roles: user.roles,
        };
        const expiredAt = moment()
            .add(1, 'day')
            .toISOString();

        const token = await this.generateToken(tokenPayload, { expiresIn });
        const confirmLink = `${this.clientAppUrl}/auth/confirm?token=${token}`;

        await this.saveToken({ token, uId: user._id, expiredAt });
        await this.mailService.send({
            from: this.configService.get<string>('JS_CODE_MAIL'),
            to: user.email,
            subject: 'Verify User',
            html: `
                <h3>Hello ${user.firstName}!</h3>
                <p>Please use this <a href="${confirmLink}">link</a> to confirm your account.</p>
            `,
        });
    }

    private async generateToken(data: ITokenPayload, options?: SignOptions): Promise<string> {
        return this.jwtService.sign(data, options);
    }

    private async verifyToken(token): Promise<any> {
        try {
            const data = this.jwtService.verify(token) as ITokenPayload;
            const tokenExists = await this.tokenService.exists(data._id, token);

            if (tokenExists) {
                return data;
            }

            throw new UnauthorizedException()
        } catch (e) {
            throw  new UnauthorizedException();
        }
    }

    private async saveToken(createUserTokenDto: CreateUserTokenDto) {
        const userToken = await this.tokenService.create(createUserTokenDto);
        return userToken;
    }

}
