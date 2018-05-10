let majesty = require('majesty')
let auth = require('../index.js');

function exec(describe, it, beforeEach, afterEach, expect, should, assert) {

    let userId = 1;
    let appId = 'testApp';
    let appExpiredId = 'tokenExpiredApp';
    let appRefreshExpiredId = 'tokenRefreshExpiredApp';
    let adminToken;
    let userToken;

    auth
        .notAuthenticatedUrls(['/', '/public'])
        .accessTokenTTL(appExpiredId, 1)
        .accessTokenTTL(appRefreshExpiredId, 1)
        .refreshTokenTTL(appRefreshExpiredId, 1);


    describe("Testes de autenticação", function () {
        describe("Acessos", function () {
            it("Deve ser possível acessar uma URL pública sem autenticação", function () {
                var canAccess = auth.middleware(mockParams(), mockRequest('/public'));
                expect(canAccess).to.equal(true);
            });

            it("Não deve ser possível acessar uma URL segura sem autenticação", function () {
                var response = mockResponse();

                var canAccess = auth.middleware(mockParams(), mockRequest('/secure'), response);
                expect(canAccess).to.equal(false);
                expect(response.status).to.equal(401);
            });

            it("Deve ser possível realizar login", function () {
                var params = mockParams();
                var request = mockRequest();
                var response = mockResponse();

                adminToken = auth.createAuthentication(params, request, response, userId, appId, {
                    roles: 'admin'
                });

                userToken = auth.createAuthentication(params, request, response, userId, appId, {
                    roles: 'user'
                });

                expect(adminToken).to.be.exist;
                expect(userToken).to.be.exist;
                expect(response.headers['Set-Cookie']).to.be.exist;
            });

            it("Deve ser possível acessar URL segura com token", function () {
                var response = mockResponse();

                var canAccess = auth.middleware(mockParams(), mockRequest('/secure', null, {
                    tkn: userToken
                }), response);

                expect(canAccess).to.equal(true);
                expect(response.status).to.equal(200);
            });
        });

        describe("Expiração do token", function () {
            it("Deve ser possível renovar um token expirado usando uma função de refresh", function () {
                var params = mockParams();
                var request = mockRequest();
                var response = mockResponse();

                let expiredToken = auth.createAuthentication(params, mockRequest(), response, userId, appExpiredId, {
                    roles: 'admin'
                });

                auth.canRefreshTokenFn(function(token) {
                    return true;
                });

                var canAccess = auth.middleware(params, mockRequest('/secure', null, {
                    tkn: expiredToken
                }), response);

                expect(canAccess).to.equal(true);
                expect(response.status).to.equal(200);
            });

            it("Deve falhar ao não possibilitar um token de ser renovado", function () {
                let calledRefreshToken = false;
                var params = mockParams();
                var request = mockRequest();
                var response = mockResponse();

                let expiredToken = auth.createAuthentication(params, mockRequest(), response, userId, appRefreshExpiredId, {
                    roles: 'admin'
                });

                auth.canRefreshTokenFn(function(token) {
                    calledRefreshToken = true;
                    return true;
                });

                var canAccess = auth.middleware(params, mockRequest('/secure', null, {
                    tkn: expiredToken
                }), response);

                expect(calledRefreshToken).to.equal(false);
                expect(canAccess).to.equal(false);
                expect(response.status).to.equal(401);
            });
        });
    });

    describe("Testes de autorização", function () {
        it("Deve setar autorizações com sucesso", function () {
            auth.authorizations({
                "/app/produtos/cadastrar": ["user"],
                "/app/produtos/*": ["admin"],
                "/app/posts/:id/comments": ["admin"]
            });
        });

        it("Deve ser possível acessar um recurso com autorização correta sem utilizar a autenticação", function () {
            var response = mockResponse();

            var canAccess = auth.validateOnlyAuthorization(mockRequest('/app/produtos/deletar'), {
                roles: 'admin'
            });

            expect(canAccess).to.equal(true);
            expect(response.status).to.equal(200);
        });

        it("Não deve ser possível acessar um recurso com autorização incorreta", function () {
            var response = mockResponse();

            var canAccess = auth.middleware(mockParams(), mockRequest('/app/produtos/deletar', null, {
                tkn: userToken
            }), response);

            expect(canAccess).to.equal(false);
            expect(response.status).to.equal(401);
        });

        it("Deve ser possível acessar um recurso com autorização correta", function () {
            var response = mockResponse();

            var canAccess = auth.middleware(mockParams(), mockRequest('/app/produtos/deletar', null, {
                tkn: adminToken
            }), response);

            expect(canAccess).to.equal(true);
            expect(response.status).to.equal(200);
        });

        it("Deve ser possível acessar um recurso com custom authorizeFn", function () {
            auth.authorizeFn(function (request, url, urlRoles, userData) {
                return urlRoles.some(function (role) {
                    return userData.roles.indexOf(role) > -1;
                });
            });

            var response = mockResponse();

            var canAccess = auth.middleware(mockParams(), mockRequest('/app/posts/10/comments', null, {
                tkn: adminToken
            }), response);

            expect(canAccess).to.equal(true);
            expect(response.status).to.equal(200);

            auth.authorizeFn(null);
        });
    });
}

function mockRequest(requestURI, headers, cookiesMap) {
    let request = {
        requestURI: requestURI,
        headers: headers || {},
        cookies: (cookiesMap && Object.keys(cookiesMap).map(function (cookieName) {
            return {
                getName: function () {
                    return cookieName;
                },
                getValue: function () {
                    return cookiesMap[cookieName];
                }
            }
        })) || []
    };

    if (cookiesMap) {

    }

    return request;
}

function mockResponse() {
    return {
        out: null,
        status: 200,
        headers: {
        },
        json: function (out, status) {
            this.out = out;

            if (status) {
                this.status = status;
            }
        },
        addHeader: function (name, value) {
            this.headers[name] = value;
        }
    }
}

function mockParams() {
    return {};
}

let res = majesty.run(exec)

print(res.success.length, " scenarios executed with success and")
print(res.failure.length, " scenarios executed with failure.\n")

res.failure.forEach(function (fail) {
    print("[" + fail.scenario + "] =>", fail.execption)
})

exit(res.failure.length);