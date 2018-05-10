Auth
===============

Auth é um *bitcode* de autenticação/autorização para [thrust](https://github.com/thrustjs/thrust) que utiliza JWT *(JSON Web Token)* como mecanismo principal.

# Instalação

Posicionado em um app [thrust](https://github.com/thrustjs/thrust), no seu terminal:

```bash
thrust install auth
```

## Tutorial

Primeiro vamos configurar nosso arquivo de inicialização *startup.js*, nele devemos fazer *require* do *auth*, configurá-lo e adicioná-lo como middleware do bitcode *router*, como mostrado abaixo:

```javascript
//Realizamos o require dos bitcodes
var server = require('http')
var router = require('router')
var auth   = require('auth')

 //O processamento de URLs é feito pelo bitcode 'url-parser'.
 //Vide as possíveis opções na documentação do mesmo.
auth
  .notAuthenticatedUrls(['/', '/public', '/auth/*'])
  .authorizations({
      "/app/produtos/cadastrar": ["user"],
      "/app/produtos/*": ["admin"],
      "/app/posts/:id/comments": ["admin"]
  });

/* Esta função de autorização não é obrigatória, e caso não informada,
a impletação padrão é a descrita abaixo, sendo que userData é o 
objeto passado como parametro para o createAuthentication.*/
auth.authorizeFn(function (url, urlRoles, userData) {
    return urlRoles.some(function (role) {
        return userData.roles.indexOf(role) > -1;
    });
});

//Adicionamos o middleware de autenticação
router.addMiddleware(auth)

//Iniciamos o servidor
server.createServer(8778, router)
```

Em seguida, devemos utilizar os métodos do *auth* que criam e destroem uma autenticação, geralmente acontece em um endpoint de login, como mostrado abaixo:

```javascript
//Rota de auth

//Realizamos o require do bitcode de autenticação
var auth   = require('authentication')

//Implementação do endpoint de login
function login (params, request, response) {

  //Checamos os parametros no banco ou qualquer outra fonte de dados.
  //Usamos apenas um if para exemplificação.
  if (params.name == 'admin' && params.password == 'admin') {

    //Criamos uma autenticação para esse usuário
    auth.createAuthentication(params, request, response, 1, 'idDoApp', {name: params.nome, role: 'admin'})

    //Respondemos ao client que deu tudo certo.
    response.json({loginOk: true})
  } else {

    //Respondemos ao client que o login falhou.
    response.json({loginOk: false, message: 'Usuário ou senha incorretos.'})
  }
}

//Implementação do endpoint de logout
function logout (params, request, response) {

  //Destruímos a autenticação
  auth.destroyAuthentication(params, request, response)
}

//Exportamos os endpoints
exports = {
  login: login,
  logout: logout
}
```

Note que, ao criar uma autenticação válida, é possível passar, como último parâmetro da função _createAuthentication_, um objeto com dados que podem ser acessados em qualquer _endpoint_, através da propriedade _userData_ no objeto _request_. Vejo abaixo como fazer isso:

```javascript
//Criando autenticação e definindo os parâmetros "name" e "role" na sessão.
auth.createAuthentication(params, request, response, 1, 'idDoApp', {name: params.nome, role: 'admin'})

//Lendo os valores das propriedades "name" e "role" informadas na criação da autenticação.
function inserirProduto(params, request, response) {
  console.log(request.userData.name)
  console.log(request.userData.role)
  //...
}
```

## Validar apenas a autorização

É possível também utilizar apenas a parte de autorização do bitcode, visto que existem aplicações onde a autenticação já é gerenciada por outros mecanismos.

Para isso, podemos configurar nosso `startup.js` da seguinte forma:

```javascript
//Realizamos o require dos bitcodes
var server = require('http')
var router = require('router')
var auth   = require('auth')

auth
  .authorizations({
      "/app/produtos/cadastrar": ["user"],
      "/app/produtos/*": ["admin"],
      "/app/posts/:id/comments": ["admin"]
  });

//Adicionamos o middleware de autorização
router.addMiddleware(function(params, request, response) {
  var canAccess = auth.validateOnlyAuthorization(request, {
    roles: 'admin'
  });
})

//Iniciamos o servidor
server.createServer(8778, router)
```

## API

```javascript
/**
* Cria um token de autenticação e o adiciona em um cookie, no header da resposta
* @param {Object} params - Parâmetros da requisição
* @param {Object} request - Request da requisição
* @param {Object} response - Response da requisição
* @param {Object} userId - Id do usuário
* @param {Object} appId - Id da aplicação (nota: uma aplicação pode conter vários ids)
* @param {Object} userData - Dados que serão incluídos no token e disponibilizados em 'request.userData'
* @example
* @file login-endpoint.js
* @code auth.createAuthentication(params, request, response, 341, 'mobileApp1', {profile: 'admin'})
*/
createAuthentication(params, request, response, userId, appId, userData)

/**
* Destrói um autenticação caso ele exista
* @param {Object} params - Parâmetros da requisição
* @param {Object} request - Request da requisição
* @param {Object} response - Response da requisição
* @example
* @file logout-endpoint.js
* @code auth.destroyAuthentication(params, request, response)
*/
destroyAuthentication(params, request, response)

/**
* Seta uma função a ser chamada para definir se um token expirado pode ser revalidado.
* @example
* @file startup.js
* @code
* auth.setCanRefreshTokenFn(function(token) {
*   return true
* })
*/
setCanRefreshTokenFn(newFn)

/**
* Função que pode ser adicionada ao auth para substituir a função padrão de autenticação.
Caso essa função não seja informada, o userData passado ao
createAuthentication deve ser informado e conter uma propriedade chamada 'roles', com as roles do usuário
* @example
* @file startup.js
* @code
* auth.authorizeFn(function(request, url, urlRoles, userData))
*/
authorizeFn(newFn)


/**
* Função que pode ser utilizada em um middleware, apenas para validar a autorização, vide exemplo de autorização sem autenticação acima.
* @example
* @file startup.js
* @code
* auth.validateOnlyAuthorization(params, request, response, userData)
*/
validateOnlyAuthorization(params, request, response, userData)

/**
* Método utilizado para setar o objeto de autorizações, sendo que a chave deve ser a URL e o valor as roles desta URL
* @example
* @file startup.js
* @code auth.authorizations({
    "/app/produtos/cadastrar": ["user"],
    "/app/produtos/*": ["admin"]
});
*/
authorizations(objAuths)

/**
* Método utilizado para setar as URLs que não necessitam de autenticação.
* @example
* @file startup.js
* @code auth.notAuthenticatedUrls(['/', '/public', '/admin/auth/*']);
*/
notAuthenticatedUrls(urls)

/**
* Método utilizado para setar a expiração do token.
* Pode ser passado como argumento apenas o tempo, que então mudará o default, ou passar junto com um nome de aplicação, que configurará apenas para esta.
* @example
* @file startup.js
* @code 
      auth.accessTokenTTL(16000); //Mudando default
      auth.accessTokenTTL('meuApp', 16000); Mudando por aplicação
*/
accessTokenTTL(ttl)
accessTokenTTL(app, ttl)

/**
* Método utilizado para setar a expiração do refresh de token.
* Pode ser passado como argumento apenas o tempo, que então mudará o default, ou passar junto com um nome de aplicação, que configurará apenas para esta.
* @example
* @file startup.js
* @code 
      auth.refreshTokenTTL(16000); //Mudando default
      auth.refreshTokenTTL('meuApp', 16000); Mudando por aplicação
*/
refreshTokenTTL(ttl)
refreshTokenTTL(app, ttl)
```

## Parâmetros de configuração
As propriedades abaixo devem ser configuradas no arquivo *config.json*:

``` javascript
...
"jwt": { /*Configuração do jwt*/
  "jwsKey": /*String*/
}
```

Exemplo:

```javascript
/**
@file config.json
*/
{
    "jwt": {
      "jwsKey": "abcdefgh12345678",
    }
}
```
Acesse também os outros *bitcodes* utilizados no exemplo para melhor entendimento:

- [thrust-bitcodes/url-parser](https://github.com/thrust-bitcodes/url-parser)
- [thrust-bitcodes/http](https://github.com/thrust-bitcodes/http)
- [thrust-bitcodes/router](https://github.com/thrust-bitcodes/router)