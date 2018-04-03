export class JwtHelper {

    public static urlBase64Decode(str: string): string {
        let output = str.replace(/-/g, '+').replace(/_/g, '/');
        switch (output.length % 4) {
            case 0: {
                break;
            }
            case 2: {
                output += '==';
                break;
            }
            case 3: {
                output += '=';
                break;
            }
            default: {
                throw 'Illegal base64url string!';
            }
        }
        return this.b64DecodeUnicode(output);
    }

    public static decodeToken(token: string): object | null {
        if (token === null || token === '') {
            return null;
        }
        let parts = token.split('.');

        if (parts.length !== 3) {
            throw new Error('The inspected token doesn\'t appear to be a JWT. Check to make sure it has three parts and see https://jwt.io for more.');
        }

        let decoded = this.urlBase64Decode(parts[1]);
        if (!decoded) {
            throw new Error('Cannot decode the token.');
        }

        return JSON.parse(decoded);
    }

    public static getTokenExpirationDate(token: string): Date | null {
        let decoded: any;
        decoded = this.decodeToken(token);

        if (!decoded.hasOwnProperty('exp')) {
            return null;
        }

        const date = new Date(0);
        date.setUTCSeconds(decoded.exp);

        return date;
    }

    public static isTokenExpired(token: string, offsetSeconds?: number): boolean {
        let date = this.getTokenExpirationDate(token);
        offsetSeconds = offsetSeconds || 0;

        if (date === null) {
            return true;
        }

        return !(date.valueOf() > new Date().valueOf() + offsetSeconds * 1000);
    }

    private static b64DecodeUnicode(str: any): string {
        return decodeURIComponent(atob(str).split('').map(JwtHelper.percentEncodeChar).join(''));
    }

    private static percentEncodeChar(char: string): string {
        return '%' + ('00' + char.charCodeAt(0).toString(16)).slice(-2);
    }
}
