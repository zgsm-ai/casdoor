// Copyright 2022 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/casdoor/casdoor/util"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/oauth2"
)

type CustomIdProvider struct {
	Client *http.Client
	Config *oauth2.Config

	UserInfoURL string
	TokenURL    string
	AuthURL     string
	UserMapping map[string]string
	Scopes      []string
}

func NewCustomIdProvider(idpInfo *ProviderInfo, redirectUrl string) *CustomIdProvider {
	idp := &CustomIdProvider{}

	idp.Config = &oauth2.Config{
		ClientID:     idpInfo.ClientId,
		ClientSecret: idpInfo.ClientSecret,
		RedirectURL:  redirectUrl,
		Endpoint: oauth2.Endpoint{
			AuthURL:  idpInfo.AuthURL,
			TokenURL: idpInfo.TokenURL,
		},
	}
	idp.UserInfoURL = idpInfo.UserInfoURL
	idp.UserMapping = idpInfo.UserMapping

	return idp
}

func (idp *CustomIdProvider) SetHttpClient(client *http.Client) {
	idp.Client = client
}

func (idp *CustomIdProvider) GetToken(code string) (*oauth2.Token, error) {
	fmt.Println("=== CustomIdProvider.GetToken 开始 ===")
	fmt.Println("授权码 code:", code)
	fmt.Println("TokenURL:", idp.Config.Endpoint.TokenURL)
	fmt.Println("ClientID:", idp.Config.ClientID)
	fmt.Println("RedirectURL:", idp.Config.RedirectURL)

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, idp.Client)
	token, err := idp.Config.Exchange(ctx, code)

	if err != nil {
		fmt.Println("Token交换失败:", err)
		return nil, err
	}

	fmt.Println("Token交换成功:")
	fmt.Println("  AccessToken:", token.AccessToken)
	fmt.Println("  TokenType:", token.TokenType)
	fmt.Println("  RefreshToken:", token.RefreshToken)
	fmt.Println("  Expiry:", token.Expiry)
	fmt.Println("=== CustomIdProvider.GetToken 结束 ===")

	return token, nil
}

type CustomUserInfo struct {
	Id          string `mapstructure:"id"`
	Username    string `mapstructure:"username"`
	DisplayName string `mapstructure:"displayName"`
	Email       string `mapstructure:"email"`
	AvatarUrl   string `mapstructure:"avatarUrl"`
}

func (idp *CustomIdProvider) GetUserInfo(token *oauth2.Token) (*UserInfo, error) {
	accessToken := token.AccessToken
	fmt.Println("=== CustomIdProvider.GetUserInfo 开始 ===")
	fmt.Println("AccessToken:", accessToken)
	fmt.Println("Token类型:", token.TokenType)
	fmt.Println("Token过期时间:", token.Expiry)
	fmt.Println("RefreshToken:", token.RefreshToken)
	fmt.Println("UserInfoURL:", idp.UserInfoURL)

	request, err := http.NewRequest("GET", idp.UserInfoURL, nil)
	if err != nil {
		fmt.Println("创建HTTP请求失败:", err)
		return nil, err
	}

	// add accessToken to request header
	authHeader := fmt.Sprintf("Bearer %s", accessToken)
	request.Header.Add("Authorization", authHeader)
	fmt.Println("Authorization头:", authHeader)
	fmt.Println("完整请求头:", request.Header)

	resp, err := idp.Client.Do(request)
	if err != nil {
		fmt.Println("HTTP请求执行失败:", err)
		return nil, err
	}
	defer resp.Body.Close()

	fmt.Println("HTTP响应状态:", resp.StatusCode)
	fmt.Println("HTTP响应头:", resp.Header)

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("读取响应体失败:", err)
		return nil, err
	}

	fmt.Println("原始响应数据:", string(data))

	var dataMap map[string]interface{}
	err = json.Unmarshal(data, &dataMap)
	if err != nil {
		fmt.Println("JSON解析失败:", err)
		return nil, err
	}
	fmt.Println("test-custom", dataMap, "  ")

	// 检查是否有错误响应
	if errcode, exists := dataMap["errcode"]; exists {
		fmt.Println("检测到API错误响应:")
		fmt.Println("  errcode:", errcode)
		if errmsg, exists := dataMap["errmsg"]; exists {
			fmt.Println("  errmsg:", errmsg)
			return nil, fmt.Errorf("IDTrust API错误: errcode=%v, errmsg=%v", errcode, errmsg)
		}
		return nil, fmt.Errorf("IDTrust API错误: errcode=%v", errcode)
	}

	requiredFields := []string{"id", "username", "displayName"}
	for _, field := range requiredFields {
		_, ok := idp.UserMapping[field]
		fmt.Println("必需字段检查 -", field, ":", ok)
		if !ok {
			return nil, fmt.Errorf("cannot find %s in userMapping, please check your configuration in custom provider", field)
		}
	}
	fmt.Println("UserMapping", idp.UserMapping)

	// map user info
	fmt.Println("=== 开始用户字段映射 ===")
	for k, v := range idp.UserMapping {
		value, ok := dataMap[v]
		fmt.Println("映射字段:", k, "->", v, ", 存在:", ok, ", 值:", value)
		if !ok {
			return nil, fmt.Errorf("cannot find %s in user from custom provider", v)
		}
		dataMap[k] = dataMap[v]
	}
	fmt.Println("映射后的数据:", dataMap)

	// try to parse id to string
	id, err := util.ParseIdToString(dataMap["id"])
	if err != nil {
		fmt.Println("ID解析失败:", err)
		return nil, err
	}
	dataMap["id"] = id
	fmt.Println("解析后的ID:", id)

	customUserinfo := &CustomUserInfo{}
	err = mapstructure.Decode(dataMap, customUserinfo)
	if err != nil {
		fmt.Println("用户信息结构体解析失败:", err)
		return nil, err
	}

	fmt.Println("解析后的用户信息:")
	fmt.Println("  Id:", customUserinfo.Id)
	fmt.Println("  Username:", customUserinfo.Username)
	fmt.Println("  DisplayName:", customUserinfo.DisplayName)
	fmt.Println("  Email:", customUserinfo.Email)
	fmt.Println("  AvatarUrl:", customUserinfo.AvatarUrl)

	userInfo := &UserInfo{
		Id:          customUserinfo.Id,
		Username:    customUserinfo.Username,
		DisplayName: customUserinfo.DisplayName,
		Email:       customUserinfo.Email,
		AvatarUrl:   customUserinfo.AvatarUrl,
	}

	fmt.Println("=== CustomIdProvider.GetUserInfo 结束 ===")
	return userInfo, nil
}
