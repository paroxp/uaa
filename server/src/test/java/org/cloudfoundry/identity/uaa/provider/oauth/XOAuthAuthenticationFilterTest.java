package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.login.AccountSavingAuthenticationSuccessHandler;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.web.client.HttpClientErrorException;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
class XOAuthAuthenticationFilterTest {

    @Mock
    private AccountSavingAuthenticationSuccessHandler mockAccountSavingAuthenticationSuccessHandler;
    @Mock
    private XOAuthAuthenticationManager mockXOAuthAuthenticationManager;
    @InjectMocks
    private XOAuthAuthenticationFilter filter;
    @Mock
    private HttpServletRequest mockHttpServletRequest;
    @Mock
    private HttpSession mockHttpSession;
    // TODO: FilterChain could live here

    @Nested
    @ExtendWith(MockitoExtension.class)
    @ExtendWith(PollutionPreventionExtension.class)
    class SetsCredentials {
        @Test
        void shouldAuthenticate() {
            MockHttpServletRequest request = new MockHttpServletRequest();
            shouldAuthenticate(filter, request, "code");
            shouldAuthenticate(filter, request, "id_token");
            shouldAuthenticate(filter, request, "access_token");
        }

        private void shouldAuthenticate(
        final XOAuthAuthenticationFilter filter,
        final MockHttpServletRequest request,
        final String pname) {
            assertFalse(filter.containsCredentials(request));
            request.setParameter(pname, "value");
            assertTrue(filter.containsCredentials(request));
            request.removeParameter(pname);
            assertFalse(filter.containsCredentials(request));
        }
    }

    @Nested
    @ExtendWith(MockitoExtension.class)
    @ExtendWith(PollutionPreventionExtension.class)
    class AuthenticationFilter {
        @BeforeEach
        void setUp() {
            // TODO: Is this the right path?
            when(mockHttpServletRequest.getPathInfo()).thenReturn("login/callback/the_origin");
            when(mockHttpServletRequest.getSession()).thenReturn(mockHttpSession);
            when(mockHttpServletRequest.getParameter(anyString())).thenReturn(null);
            when(mockHttpServletRequest.getParameter("state")).thenReturn("the_state");

            when(mockHttpSession.getAttribute("xoauth-state-the_origin")).thenReturn("the_state");
        }

        @BeforeEach
        @AfterEach
        void clearContext() {
            SecurityContextHolder.clearContext();
        }

        @Test
        void getIdTokenInResponse() throws Exception {
            when(mockHttpServletRequest.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
            when(mockHttpServletRequest.getParameter("id_token")).thenReturn("the_id_token");
            when(mockHttpServletRequest.getParameter("access_token")).thenReturn("the_access_token");
            when(mockHttpServletRequest.getParameter("code")).thenReturn("the_code");

            UaaAuthentication authentication = mock(UaaAuthentication.class);
            Mockito.when(mockXOAuthAuthenticationManager.authenticate(any())).thenReturn(authentication);

            FilterChain chain = mock(FilterChain.class);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(mockHttpServletRequest, response, chain);

            ArgumentCaptor<XOAuthCodeToken> captor = ArgumentCaptor.forClass(XOAuthCodeToken.class);
            verify(mockXOAuthAuthenticationManager).authenticate(captor.capture());
            verify(chain).doFilter(mockHttpServletRequest, response);

            XOAuthCodeToken xoAuthCodeToken = captor.getValue();
            assertEquals("the_access_token", xoAuthCodeToken.getAccessToken());
            assertEquals("the_id_token", xoAuthCodeToken.getIdToken());
            assertEquals("the_code", xoAuthCodeToken.getCode());
            assertEquals("the_origin", xoAuthCodeToken.getOrigin());
            assertEquals("http://localhost/uaa/login/callback/the_origin", xoAuthCodeToken.getRedirectUrl());
            assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
        }

        @Test
        void getXOAuthCodeTokenFromRequest() throws Exception {
            when(mockHttpServletRequest.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
            when(mockHttpServletRequest.getParameter("code")).thenReturn("the_code");

            UaaAuthentication authentication = mock(UaaAuthentication.class);
            Mockito.when(mockXOAuthAuthenticationManager.authenticate(any())).thenReturn(authentication);

            FilterChain chain = mock(FilterChain.class);
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(mockHttpServletRequest, response, chain);

            ArgumentCaptor<XOAuthCodeToken> captor = ArgumentCaptor.forClass(XOAuthCodeToken.class);
            verify(mockXOAuthAuthenticationManager).authenticate(captor.capture());
            verify(chain).doFilter(mockHttpServletRequest, response);

            XOAuthCodeToken xoAuthCodeToken = captor.getValue();
            assertEquals("the_code", xoAuthCodeToken.getCode());
            assertEquals("the_origin", xoAuthCodeToken.getOrigin());
            assertEquals("http://localhost/uaa/login/callback/the_origin", xoAuthCodeToken.getRedirectUrl());
            assertEquals(authentication, SecurityContextHolder.getContext().getAuthentication());
            assertNull(xoAuthCodeToken.getIdToken());
            assertNull(xoAuthCodeToken.getAccessToken());
        }

        @Test
        void redirectsToErrorPageInCaseOfException() throws Exception {
            FilterChain chain = mock(FilterChain.class);
            MockHttpServletResponse response = new MockHttpServletResponse();

            when(mockHttpServletRequest.getRequestURL()).thenReturn(new StringBuffer("http://localhost/uaa/login/callback/the_origin"));
            when(mockHttpServletRequest.getParameter("code")).thenReturn("the_code");

            Mockito.doThrow(new HttpClientErrorException(HttpStatus.BAD_REQUEST, "error from oauth server")).when(mockXOAuthAuthenticationManager).authenticate(any());
            filter.doFilter(mockHttpServletRequest, response, chain);
            assertThat(response.getHeader("Location"), Matchers.containsString(mockHttpServletRequest.getContextPath() + "/oauth_error?error=There+was+an+error+when+authenticating+against+the+external+identity+provider%3A"));
        }

        @Test
        void doesNotThrowIfStateParamCorrect() {
            when(mockHttpServletRequest.getParameter("state")).thenReturn("the_state");
            MockRequestDispatcher mockRequestDispatcher = new MockRequestDispatcher("/login_implicit");
            when(mockHttpServletRequest.getRequestDispatcher("/login_implicit")).thenReturn(mockRequestDispatcher);

            FilterChain chain = mock(FilterChain.class);
            MockHttpServletResponse response = new MockHttpServletResponse();
            assertDoesNotThrow(() -> filter.doFilter(mockHttpServletRequest, response, chain));
        }

        @Test
        void throwsIfStateParamIncorrect() {
            when(mockHttpServletRequest.getParameter("state")).thenReturn("stateInParameter");

            FilterChain chain = mock(FilterChain.class);
            MockHttpServletResponse response = new MockHttpServletResponse();
            assertThrows(CsrfException.class, () -> filter.doFilter(mockHttpServletRequest, response, chain));
        }
    }
}
