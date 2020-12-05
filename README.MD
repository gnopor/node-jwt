# Node js JWT authentication and authorization server

## Workflow

### Launch node sever

`
npm i

npm run start
`

### Test API

**All the folowing endpoint user http post request**
_/register and /login need one object containing the email and password_

`
{
email: 'some fucking email string',
password: 'some fucking password string'

}
`

### EndPoints

1. http://localhost:4000/register

2. http://localhost:4000/login

3. http://localhost:4000/protected

4. http://localhost:4000/refresh_token

5. http://localhost:4000/logout

Original Source: [Source](https://www.youtube.com/watch?v=x5gLL8-M9Fo&t=2740s&ab_channel=freeCodeCamp.org)
