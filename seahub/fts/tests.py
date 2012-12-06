# encoding: utf-8
import os
import time

from django.test import TestCase, Client
from django_liveserver.testcases import LiveServerTestCase
from selenium import webdriver
from selenium.webdriver.firefox.webdriver import WebDriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys

from seahub.base.accounts import User
from seaserv import list_personal_repos_by_owner, remove_repo

class BaseTest(LiveServerTestCase):
    
    def setUp(self):
        self.site_url = 'localhost:8000'

        self.username = 'foo@foo.com'
        self.passwd = 'foo'
        self.browser = webdriver.Firefox()
        self.browser.implicitly_wait(3)

    def tearDown(self):
        self.browser.quit()

    def _setup_new_user(self, username, passwd):
        User.objects.create_user(username, passwd, False, True)

    def _teardown_new_user(self, username):
        # First delete all repos created by user
        for e in list_personal_repos_by_owner(username):
            remove_repo(e.id)
        # Then remove user
        User.objects.get(email=username).delete()

    def _login_user(self, username=None, passwd=None):
        if not (username and passwd):
            username = self.username
            passwd = self.passwd

        self._setup_new_user(username, passwd)
        # A user goes to the login page, and inputs username and password
        self.browser.get(self.site_url+ '/accounts/login/')
        username_field = self.browser.find_element_by_name('username')
        username_field.send_keys(username)
        password_field = self.browser.find_element_by_name('password')
        password_field.send_keys(passwd)
        password_field.send_keys(Keys.RETURN)

        # He is returned to myhome page
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn(u'Libraries', body.text)

    def _logout_user(self, username=None, remove_user=True):
        if not username:
            username = self.username
        self.browser.find_elements_by_link_text(u'Log out')[0].click()
        if remove_user:
            self._teardown_new_user(username)
        
    def _create_new_library(self, name, desc, read_only=False, encrypt=False,
                            passwd=None):
        # He sees a button to 'add' a new repo, so he clicks it
        new_repo_btn = self.browser.find_element_by_css_selector("#repo-create")
        new_repo_btn.click()

        # He sees some input fields for "Name" and "description", etc
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn(u'Name', body.text)
        self.assertIn(u'Description', body.text)

        # He types in an test repo
        reponame_field = self.browser.find_element_by_name('repo_name')
        reponame_field.send_keys(name)
        repodesc_field = self.browser.find_element_by_name('repo_desc')
        repodesc_field.send_keys(desc)
        if encrypt:
            self.assertNotEquals(passwd, None)
            self.browser.find_element_by_name('encryption').click()
            self.browser.find_element_by_name('passwd').send_keys(passwd)
            self.browser.find_element_by_name('passwd_again').send_keys(passwd)
        if read_only:
            self.browser.find_element_by_css_selector('option ~ option').click()

        # He clicks the submit button
        sub_btn = self.browser.find_element_by_css_selector("#repo-create-submit")
        sub_btn.click()

        # He is returned to the myhome page, where he can see his new repo,
        # listed as a clickable link
        new_repo_links = self.browser.find_elements_by_link_text(name)
        self.assertNotEquals(len(new_repo_links), 0)
        
    def _destroy_library(self, repo_name):
        # He moves mouse to the table list
        while(len(self.browser.find_elements_by_link_text(repo_name)) != 0):
            ActionChains(self.browser).move_to_element(self.browser.find_elements_by_link_text(repo_name)[0]).perform()
            # He sees a delete icon, and click it
            del_btn = self.browser.find_element_by_css_selector('.repo-delete-btn')
            del_btn.click()
            # There pops a confirm dialog, so he click confirm button
            self.assertIn('Delete Library', self.browser.find_element_by_css_selector('#confirm-con').text)
            self.browser.find_element_by_css_selector('#confirm-yes').click()
            time.sleep(0.2)
        # Now there is no repo has that name
        self.assertEquals(len(self.browser.find_elements_by_link_text(repo_name)), 0)

    def _create_new_folder(self, folder_name):
        # He clicks the New Directory button
        self.browser.find_element_by_css_selector('#add-new-dir').click()
        new_dir_input = self.browser.find_element_by_name('new_dir_name')
        new_dir_input.send_keys(folder_name)
        new_dir_input.send_keys(Keys.RETURN)

    def _create_new_file(self, file_name, file_type='txt'):
        # He clicks the New File button
        self.browser.find_element_by_css_selector('#add-new-file').click()
        
        if file_type == 'txt':
            # He inputs file name and press Enter button
            new_file_input = self.browser.find_element_by_name('new_file_name')
            new_file_input.send_keys(file_name)
            new_file_input.send_keys(Keys.RETURN)
        else:
            self.fail('TODO')

class AccountTest(BaseTest):
    def test_can_modify_personal_infos(self):
        self._login_user()

        self.browser.find_element_by_css_selector('.home-profile .avatar').click()
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn(u'Profile Setting', body.text)

        nickname_field = self.browser.find_element_by_name('nickname')
        nickname_field.clear()
        nickname_field.send_keys(u'test_nickname2012')

        intro_field = self.browser.find_element_by_name('intro')
        intro_field.clear()
        intro_field.send_keys('Hi, My name is test.')
        
        self.browser.find_element_by_css_selector('.submit').click()

        body = self.browser.find_element_by_tag_name('body')
        self.assertIn(u'Successfully', body.text)

        self._logout_user()

class LibraryTest(BaseTest):
    def test_can_create_new_library(self):
        self._login_user()

        '''Create a unencrypt repo'''
        self._create_new_library('test_repo', 'test repo desc')
        self.browser.find_elements_by_link_text('test_repo')[0].click()
        # He is returned to the repo page, where he can view/add files or directories
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('Upload', body.text)
        # He backs to Myhome page
        self.browser.find_elements_by_link_text('My Home')[0].click()
        
        '''Create an encrypte repo'''
        passwd = '123'
        self._create_new_library('test_enc_repo', 'test repo desc', encrypt=True,
                                 passwd=passwd)
        self.browser.find_elements_by_link_text('test_enc_repo')[0].click()
        # He is returned to the repo decryption page, where he can input passwords
        self.assertIn('Password', self.browser.find_element_by_tag_name('body').text)
        # He inputs the password
        passwd_input = self.browser.find_element_by_name('password')
        passwd_input.send_keys(passwd)
        passwd_input.send_keys(Keys.RETURN)
        # He is returned to the repo page, where he can view/add files or directories
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('Upload', body.text)
        # He backs to Myhome page
        self.browser.find_elements_by_link_text('My Home')[0].click()

        self._logout_user()

    def test_can_destroy_library(self):
        self._login_user()

        self._create_new_library('test_repo', 'test repo desc')
        self._destroy_library('test_repo')

        self._logout_user()

    def test_can_view_readonly_library(self):
        self._login_user()

        '''Create read-only repo in Public Library'''
        self.browser.find_elements_by_link_text('Public Library')[0].click()
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('Public Libraries', body.text)
        self._create_new_library('test_readonly_repo', 'test read only repo',
                                 read_only=True)
        # He clicks the readonly library name
        self.browser.find_elements_by_link_text('test_readonly_repo')[0].click()
        # He is returned to the repo page, where he can view/add files or directories
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('Upload', body.text)
        self._logout_user(remove_user=False)

        # Another user login and click this readonly repo
        self._login_user('bar@bar.com', 'bar')
        self.browser.find_elements_by_link_text('Public Library')[0].click()
        self.browser.find_elements_by_link_text('test_readonly_repo')[0].click()
        # He can only view repo contents, but not upload or new files
        body = self.browser.find_element_by_tag_name('body')
        self.assertNotIn('Upload', body.text)
        self._logout_user(username='bar@bar.com')

        # Clean first user's libraries
        self._login_user()
        self._logout_user()

class FolderTest(BaseTest):
    def test_folder_operations(self):
        self._login_user()

        # He create a new repo, clicked the repo name, and returned to the
        # repo page
        self._create_new_library('test_repo', 'test desc')
        self.browser.find_elements_by_link_text('test_repo')[0].click()

        # He creates two folders
        self._create_new_folder('dir1')
        self.assertNotEquals(self.browser.find_elements_by_link_text('dir1'), None)
        self._create_new_folder('dir2')
        self.assertNotEquals(self.browser.find_elements_by_link_text('dir2'), None)

        '''Moving folder `dir1` to `dir2`'''
        # He move mouse to directory table list
        ele_to_hover_over = self.browser.find_elements_by_link_text('dir1')[0]
        hover = ActionChains(self.browser).move_to_element(ele_to_hover_over)
        hover.perform()

        # He clicks more op icon adn chooses move operation
        more_op = self.browser.find_element_by_css_selector('.repo-file-list .more-op-icon')
        more_op.click()
        self.browser.find_elements_by_link_text('Move')[0].click()

        # He selects dir2 to move in, and click submit button
        self.browser.find_element_by_css_selector('.jstree-default .jstree-closed ins').click()
        self.browser.find_element_by_css_selector('.jstree-leaf a').click()
        self.browser.find_element_by_css_selector('#mv-form .submit').click()
        time.sleep(1)

        # He sees seccessfull message
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('Successfully moving', body.text)

        '''Rename folder `dir2` to `dir3`'''
        # He move mouse to directory table list
        ele_to_hover_over = self.browser.find_elements_by_link_text('dir2')[0]
        hover = ActionChains(self.browser).move_to_element(ele_to_hover_over)
        hover.perform()

        # He clicks more op icon adn chooses move operation
        more_op = self.browser.find_element_by_css_selector('.repo-file-list .more-op-icon')
        more_op.click()
        self.browser.find_elements_by_link_text('Rename')[0].click()
        newname_input = self.browser.find_element_by_name('newname')
        newname_input.clear()
        newname_input.send_keys('dir3')
        newname_input.send_keys(Keys.RETURN)
        time.sleep(1)
        # He sees seccessfull message
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('Successfully rename', body.text)

        '''Delete folder `dir3`'''
        # He move mouse to directory table list
        ele_to_hover_over = self.browser.find_elements_by_link_text('dir3')[0]
        hover = ActionChains(self.browser).move_to_element(ele_to_hover_over)
        hover.perform()

        # He clicks more op icon adn chooses move operation
        more_op = self.browser.find_element_by_css_selector('.repo-file-list .more-op-icon')
        more_op.click()
        self.browser.find_elements_by_link_text('Delete')[0].click()
        time.sleep(1)
        # He sees seccessfull message
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('successfully deleted', body.text)

        self._logout_user()
    
class FileTest(BaseTest):
    def test_file_operations(self):
        self._login_user()

        # He create a new repo, clicked the repo name, and returned to the
        # repo page
        self._create_new_library('test_repo', 'test desc')
        self.browser.find_elements_by_link_text('test_repo')[0].click()

        # He creates a new file
        self._create_new_file('test.txt')
        self.assertNotEquals(self.browser.find_elements_by_link_text('test.txt'), None)

        '''Rename file `test.txt` to `test2.txt`'''
        # He move mouse to directory table list
        ele_to_hover_over = self.browser.find_elements_by_link_text('test.txt')[0]
        hover = ActionChains(self.browser).move_to_element(ele_to_hover_over)
        hover.perform()
        # He clicks more op icon adn chooses move operation
        more_op = self.browser.find_element_by_css_selector('.repo-file-list .more-op-icon')
        more_op.click()
        self.browser.find_elements_by_link_text('Rename')[0].click()
        h3 = self.browser.find_element_by_css_selector('#simplemodal-container h3')
        self.assertIn('Rename', h3.text)
        newname_input = self.browser.find_element_by_name('newname')
        newname_input.clear()
        newname_input.send_keys('test2.txt')
        newname_input.send_keys(Keys.RETURN)
        time.sleep(1)
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('Successfully rename', body.text)

        self._logout_user()
        
    def test_edit_file(self):
        self._login_user()

        # He create a new repo, clicked the repo name, and returned to the
        # repo page
        self._create_new_library('test_repo', 'test desc')
        self.browser.find_elements_by_link_text('test_repo')[0].click()

        '''TXT File'''
        # He creates a txt file
        self._create_new_file('test.txt', file_type='txt')
        # He clicks the file name, and returned to the file viewing page
        self.browser.find_elements_by_link_text('test.txt')[0].click()
        h2 = self.browser.find_element_by_tag_name('h2')
        self.assertIn('test.txt', h2.text)
        # He wants to type some texts, so he clicks Edit button
        self.browser.find_element_by_css_selector('#edit').click()
        # He returned to the file editing page
        h2 = self.browser.find_element_by_tag_name('h2')
        self.assertIn('Edit', h2.text)
        # He types some text, and click submit button to save changes
        for i in range(0, 5):
            ActionChains(self.browser).send_keys('Hello, world').perform()
            ActionChains(self.browser).send_keys(Keys.RETURN).perform()
        self.browser.find_element_by_css_selector('#file-edit-submit').click()
        time.sleep(1)
        body = self.browser.find_element_by_tag_name('body')
        self.assertIn('Hello, world', body.text)

        self._logout_user()

