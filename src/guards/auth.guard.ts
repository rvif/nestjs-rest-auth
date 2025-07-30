import {
    Injectable,
    CanActivate,
    ExecutionContext,
    UnauthorizedException,
    Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate
{
    constructor(private readonly jwtService: JwtService)
    {}

    canActivate(
        context: ExecutionContext,
    ): boolean | Promise<boolean> | Observable<boolean>
    {
        const request: Request = context.switchToHttp().getRequest();
        const token = this.extractTokenFromHeader(request);

        if (!token)
        {
            // return false // forbidden 403 (default for guards)
            throw new UnauthorizedException('Invalid Token');
        }
        try
        {
            const payload = this.jwtService.verify(token); // throws an error if token has expired or if signature (secret) doesnt match
            // attach payload to request
            request.userId = payload.userId;
        }
        catch (e)
        {
            Logger.error(e.message);
            throw new UnauthorizedException('Invalid Token');
        }

        return true;
    }

    private extractTokenFromHeader(request: Request): string | undefined
    {
        return request.headers.authorization?.split(' ')[1];
    }
}
