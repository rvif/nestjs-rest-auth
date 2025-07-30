import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService
{
    private transporter: nodemailer.Transporter;

    constructor()
    {
        this.transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            auth: {
                // Just for testing, in real application store the following in .env
                user: 'nicholaus14@ethereal.email',
                pass: 'pFFzu7STQt88d15a1j',
            },
        });
    }

    async sendPasswordResetEmail(to: string, token: string)
    {
        const resetLink = `http://my-app-frontend.com/reset-password?token=${token}`;
        const mailOptions = {
            from: 'Auth-backend service',
            to: to, // recipient email
            subject: 'Password Reset Request',
            html: `<p>You requested a password reset. Click the link below to reset your password:</p><p><a href="${resetLink}">Reset Password</a></p>`,
        };

        await this.transporter.sendMail(mailOptions);
    }
}
