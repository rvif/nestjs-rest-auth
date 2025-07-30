import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { DatabaseModule } from 'src/database/database.module';
import { MailService } from 'src/services/mail.service';

@Module({
    imports: [DatabaseModule],
    controllers: [AuthController],
    providers: [AuthService, MailService],
    // inject MailService as one of the providers so that we can use it as a dependency in this module
})
export class AuthModule
{}
