<?php
/**
 * @author Christoph Wurst <christoph@owncloud.com>
 * @author Joas Schilling <coding@schilljs.com>
 * @author Lukas Reschke <lukas@statuscode.ch>
 * @author Semih Serhat Karakaya <karakayasemi@itu.edu.tr>
 * @author Thomas Müller <thomas.mueller@tmit.eu>
 *
 * @copyright Copyright (c) 2018, ownCloud GmbH
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

namespace OC\Core\Controller;

use OC\Authentication\TwoFactorAuth\Manager;
use OC\User\Session;
use OC_App;
use OC_Util;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\License\ILicenseManager;
use OCP\IConfig;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use \OCP\ILogger;


class LoginController extends Controller {

	/** @var IUserManager */
	private $userManager;

	/** @var IConfig */
	private $config;

	/** @var ISession */
	private $session;

	/** @var Session */
	private $userSession;

	/** @var IURLGenerator */
	private $urlGenerator;

	/** @var Manager */
	private $twoFactorManager;

	/** @var ILicenseManager */
	private $licenseManager;

	private $OAUTH_URL;
	private $REDIRECT_URL;
	/**
	 * @param string $appName
	 * @param IRequest $request
	 * @param IUserManager $userManager
	 * @param IConfig $config
	 * @param ISession $session
	 * @param Session $userSession
	 * @param IURLGenerator $urlGenerator
	 * @param Manager $twoFactorManager
	 */
	public function __construct($appName, IRequest $request, IUserManager $userManager, IConfig $config, ISession $session,
		Session $userSession, IURLGenerator $urlGenerator, Manager $twoFactorManager, ILicenseManager $licenseManager) {
		parent::__construct($appName, $request);
		$this->userManager = $userManager;
		$this->config = $config;
		$this->session = $session;
		$this->userSession = $userSession;
		$this->urlGenerator = $urlGenerator;
		$this->twoFactorManager = $twoFactorManager;
		$this->licenseManager = $licenseManager;
		$this->OAUTH_URL="https://oauth.threefold.io";
		$this->REDIRECT_URL="https://login.threefold.me";
		
	}

	/**
	 * @NoAdminRequired
	 * @UseSession
	 *
	 * @return RedirectResponse
	 */
	public function logout() {
		$loginToken = $this->request->getCookie('oc_token');
		if ($loginToken !== null) {
			$this->config->deleteUserValue($this->userSession->getUser()->getUID(), 'login_token', $loginToken);
		}
		$this->userSession->logout();

		return new RedirectResponse($this->urlGenerator->linkToRouteAbsolute('core.login.showLoginForm'));
	}

	/**
	 * @PublicPage
	 * @NoCSRFRequired
	 * @UseSession
	 *
	 * @param string $user
	 * @param string $redirect_url
	 * @param string $remember_login
	 *
	 * @return TemplateResponse|RedirectResponse
	 */
	public function showLoginForm($user, $redirect_url, $remember_login) {
		if (\OC_User::handleApacheAuth() || $this->userSession->isLoggedIn()) {
			return new RedirectResponse($this->getDefaultUrl());
		}

		$parameters = [];
		$loginMessages = $this->session->get('loginMessages');
		$errors = [];
		$messages = [];
		if (\is_array($loginMessages)) {
			list($errors, $messages) = $loginMessages;
		}
		$this->session->remove('loginMessages');
		foreach ($errors as $value) {
			$parameters[$value] = true;
		}

		$parameters['messages'] = $messages;
		if ($user !== null && $user !== '') {
			$parameters['loginName'] = $user;
			$parameters['user_autofocus'] = false;
		} else {
			$parameters['loginName'] = '';
			$parameters['user_autofocus'] = true;
		}
		if (!empty($redirect_url)) {
			$parameters['redirect_url'] = $redirect_url;
		}

		$parameters['canResetPassword'] = true;
		$parameters['resetPasswordLink'] = $this->config->getSystemValue('lost_password_link', '');
		if (!$parameters['resetPasswordLink']) {
			if ($user !== null && $user !== '') {
				$userObj = $this->userManager->get($user);
				if ($userObj instanceof IUser) {
					$parameters['canResetPassword'] = $userObj->canChangePassword();
				}
			}
		} elseif ($parameters['resetPasswordLink'] === 'disabled') {
			$parameters['canResetPassword'] = false;
		}

		$altLogins = OC_App::getAlternativeLogIns();
		$altLogins2 = $this->config->getSystemValue('login.alternatives');
		if (\is_array($altLogins2) && !empty($altLogins2)) {
			$altLogins = \array_merge($altLogins, $altLogins2);
		}
		$parameters['alt_login'] = $altLogins;
		$parameters['rememberLoginAllowed'] = OC_Util::rememberLoginAllowed();
		$parameters['rememberLoginState'] = !empty($remember_login) ? $remember_login : 0;

		if ($user !== null && $user !== '') {
			$parameters['loginName'] = $user;
			$parameters['user_autofocus'] = false;
		} else {
			$parameters['loginName'] = '';
			$parameters['user_autofocus'] = true;
		}

		/**
		 * If redirect_url is not empty and remember_login is null and
		 * user not logged in and check if the string
		 * webroot+"/index.php/f/" is in redirect_url then
		 * user is trying to access files for which he needs to login.
		 */

		if (!empty($redirect_url) && ($remember_login === null) &&
			($this->userSession->isLoggedIn() === false) &&
			(\strpos($this->urlGenerator->getAbsoluteURL(\urldecode($redirect_url)),
					$this->urlGenerator->getAbsoluteURL('/index.php/f/')) !== false)) {
			$parameters['accessLink'] = true;
		}

		$licenseMessageInfo = $this->licenseManager->getLicenseMessageFor('core');
		// show license message only if there is a license
		$licenseState = $licenseMessageInfo['license_state'];
		if ($licenseState !== ILicenseManager::LICENSE_STATE_MISSING) {
			// license type === 1 implies it's a demo license
			if ($licenseMessageInfo['type'] === 1 ||
				($licenseState !== ILicenseManager::LICENSE_STATE_VALID &&
					$licenseState !== ILicenseManager::LICENSE_STATE_ABOUT_TO_EXPIRE)
			) {
				$parameters['licenseMessage'] = \implode('<br/>', $licenseMessageInfo['translated_message']);
			}
		}

		$parameters['strictLoginEnforced'] = $this->config->getSystemValue('strict_login_enforced', false);

		return new TemplateResponse(
			$this->appName, 'login', $parameters, 'guest'
		);
	}

	/**
	 * @PublicPage
	 * @UseSession
	 *
	 * @param string $user
	 * @param string $password
	 * @param string $redirect_url
	 * @param string $timezone
	 * @return RedirectResponse
	 * @throws \OCP\PreConditionNotMetException
	 * @throws \OC\User\LoginException
	 */
	public function tryLogin($user, $password, $redirect_url,$type="normal" , $timezone = null) {
		

		if ($type=="tfconnect"){
			$this->tryTFLogin();
		}





		$originalUser = $user;
		// TODO: Add all the insane error handling
		$loginResult = $this->userSession->login($user, $password);
		if ($loginResult !== true && $this->config->getSystemValue('strict_login_enforced', false) !== true) {
			$users = $this->userManager->getByEmail($user);
			// we only allow login by email if unique
			if (\count($users) === 1) {
				$user = $users[0]->getUID();
				$loginResult = $this->userSession->login($user, $password);
			}
		}
		if ($loginResult !== true) {
			$this->session->set('loginMessages', [
				['invalidpassword'], []
			]);
			$args = [];
			// Read current user and append if possible - we need to return the unmodified user otherwise we will leak the login name
			if ($user !== null) {
				$args['user'] = $originalUser;
			}
			// keep the redirect url
			if (!empty($redirect_url)) {
				$args['redirect_url'] = $redirect_url;
			}
			return new RedirectResponse($this->urlGenerator->linkToRoute('core.login.showLoginForm', $args));
		}
		/* @var $userObject IUser */
		$userObject = $this->userSession->getUser();
		// TODO: remove password checks from above and let the user session handle failures
		// requires https://github.com/owncloud/core/pull/24616
		$this->userSession->createSessionToken($this->request, $userObject->getUID(), $user, $password);

		// User has successfully logged in, now remove the password reset link, when it is available
		$this->config->deleteUserValue($userObject->getUID(), 'owncloud', 'lostpassword');

		// Save the timezone
		if ($timezone !== null) {
			$this->config->setUserValue($userObject->getUID(), 'core', 'timezone', $timezone);
		}

		if ($this->twoFactorManager->isTwoFactorAuthenticated($userObject)) {
			$this->twoFactorManager->prepareTwoFactorLogin($userObject);
			if ($redirect_url !== null) {
				return new RedirectResponse($this->urlGenerator->linkToRoute('core.TwoFactorChallenge.selectChallenge', [
					'redirect_url' => $redirect_url
				]));
			}
			return new RedirectResponse($this->urlGenerator->linkToRoute('core.TwoFactorChallenge.selectChallenge'));
		}

		if ($redirect_url !== null && $this->userSession->isLoggedIn()) {
			$location = $this->urlGenerator->getAbsoluteURL(\urldecode($redirect_url));
			// Deny the redirect if the URL contains a @
			// This prevents unvalidated redirects like ?redirect_url=:user@domain.com
			if (\strpos($location, '@') === false) {
				return new RedirectResponse($location);
			}
		}

		return new RedirectResponse($this->getDefaultUrl());
	}

	/**
	 * @PublicPage
	 * @UseSession
	 *
	 * @param string $user
	 * @param string $password
	 * @param string $redirect_url
	 * @param string $timezone
	 * @return RedirectResponse
	 * @throws \OCP\PreConditionNotMetException
	 * @throws \OC\User\LoginException
	 */
	public function tryTFLogin(){
		$state = $this->random_str(32,"0123456789abcdef"); 
		$this->session->set("state",$state);
		$ch = curl_init($this->OAUTH_URL . "/pubkey");
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		$res=curl_exec($ch);
		curl_close($ch);
		$res = json_decode($res, true);
		$pubkey = $res['publickey'];
		$data = [
			"user" => true,
			"email" => true
		];
		$appid = $this->request->getHeader("Host");
		$params=[
			"state" => $state,
			"appid" => $appid,
			"scope" => json_encode($data), 
			"redirecturl" =>"/index.php/callback",
			"publickey" => utf8_encode($pubkey),
		];
		$params = http_build_query($params);
		$url = $this->REDIRECT_URL.'?'.$params;
		header("Location: $url");
		exit();

	}

	/**
	 * @PublicPage
	 * @UseSession
	 *
	 * @param string $user
	 * @param string $password
	 * @param string $redirect_url
	 * @param string $timezone
	 * @return RedirectResponse
	 * @throws \OCP\PreConditionNotMetException
	 * @throws \OC\User\LoginException
	 */
	public function callback(){
		$session = $this->session->get('state');
		$signAttempt = $this->request->getParam("signedAttempt","");
		$data = [
			"signedAttempt"=>$signAttempt,
			"state" => $session
		];
		$url = $this->OAUTH_URL . "/verify";
		$ch = curl_init($this->OAUTH_URL . "/verify");
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
		curl_setopt($ch, CURLINFO_HEADER_OUT, true);
		$res=curl_exec($ch);
		curl_close($ch);

		$res = json_decode($res,true);
		$user = $res['username'];
		$email = $res['email'];
		$password = $this->random_str(10);
		$loginResult = $this->userSession->tflogin($user, $password,$email);


		// TODO: separate the next login in another method 
		if ($loginResult !== true) {
			$this->session->set('loginMessages', [
				['invalidpassword'], []
			]);
			$args = [];
			// Read current user and append if possible - we need to return the unmodified user otherwise we will leak the login name
			if ($user !== null) {
				$args['user'] = $originalUser;
			}
			// keep the redirect url
			if (!empty($redirect_url)) {
				$args['redirect_url'] = $redirect_url;
			}
			return new RedirectResponse($this->urlGenerator->linkToRoute('core.login.showLoginForm', $args));
		}
		/* @var $userObject IUser */
		$userObject = $this->userSession->getUser();
		// TODO: remove password checks from above and let the user session handle failures
		// requires https://github.com/owncloud/core/pull/24616
		$this->userSession->createSessionToken($this->request, $userObject->getUID(), $user, $password);

		// User has successfully logged in, now remove the password reset link, when it is available
		$this->config->deleteUserValue($userObject->getUID(), 'owncloud', 'lostpassword');

		// Save the timezone
		if ($timezone !== null) {
			$this->config->setUserValue($userObject->getUID(), 'core', 'timezone', $timezone);
		}

		if ($this->twoFactorManager->isTwoFactorAuthenticated($userObject)) {
			$this->twoFactorManager->prepareTwoFactorLogin($userObject);
			if ($redirect_url !== null) {
				return new RedirectResponse($this->urlGenerator->linkToRoute('core.TwoFactorChallenge.selectChallenge', [
					'redirect_url' => $redirect_url
				]));
			}
			return new RedirectResponse($this->urlGenerator->linkToRoute('core.TwoFactorChallenge.selectChallenge'));
		}

		if ($redirect_url !== null && $this->userSession->isLoggedIn()) {
			$location = $this->urlGenerator->getAbsoluteURL(\urldecode($redirect_url));
			// Deny the redirect if the URL contains a @
			// This prevents unvalidated redirects like ?redirect_url=:user@domain.com
			if (\strpos($location, '@') === false) {
				return new RedirectResponse($location);
			}
		}

		return new RedirectResponse($this->getDefaultUrl());
	
	}
	
	/**
	 * @return string
	 */
	protected function getDefaultUrl() {
		return OC_Util::getDefaultPageUrl();
	}

	/**
	 * @return ISession
	 */
	public function getSession() {
		return $this->session;
	}
	
	/**
	 * Generate a random string, using a cryptographically secure 
	 * pseudorandom number generator (random_int)
	 * 
	 * For PHP 7, random_int is a PHP core function
	 * For PHP 5.x, depends on https://github.com/paragonie/random_compat
	 * 
	 * @param int $length      How many characters do we want?
	 * @param string $keyspace A string of all possible characters
	 *                         to select from
	 * @return string
	 */
	protected function random_str(
		$length,
		$keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	) {
		$str = '';
		$max = mb_strlen($keyspace, '8bit') - 1;
		if ($max < 1) {
			throw new Exception('$keyspace must be at least two characters long');
		}
		for ($i = 0; $i < $length; ++$i) {
			$str .= $keyspace[random_int(0, $max)];
		}
		return $str;
	}
}
