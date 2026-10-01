# FNCache Contributor Ladder

## 1. 目的与适用范围

本文定义 FNCache 项目的贡献者身份、晋升关系和 GitHub 仓库权限映射。

`FNCache-project` 组织只服务于 FNCache 核心项目及其官方生态项目。本文适用于组织拥有的核心仓库和后续纳入组织的官方生态仓库。

本文定义的是项目角色和权限原则，不替代 GitHub 的具体设置。GitHub 的仓库权限用于执行本文规定的最小权限边界。

## 2. 基本原则

1. Contributor 是默认状态，不需要加入组织或获得 GitHub 仓库权限。
2. 组织成员身份和具体仓库权限分别管理；加入组织不等于自动获得所有仓库的高权限。
3. 权限按实际贡献和责任逐级授予，遵循最小权限原则。
4. Reviewer 的权限限定在明确的仓库和模块范围内。
5. Admin 是高风险仓库管理权限，不是普通贡献者晋升的必经等级。
6. 角色授予、变更和撤销都应保留可审计记录。
7. 公开贡献不要求事先获得组织邀请。

## 3. 角色与 GitHub 权限

| 项目角色 | 组织身份 | 具体仓库权限 | 主要能力 |
| --- | --- | --- | --- |
| Contributor | 非组织成员 | 无额外权限 | Fork、Issue、Discussion、Pull Request |
| Member | Organization Member | Triage | 管理 Issue/PR、标签、分配和评审请求 |
| Reviewer | Organization Member | Write | 在指定模块审查、批准或要求修改 PR |
| Maintainer | Organization Member | Maintain | 维护仓库、合并符合要求的 PR、参与项目维护 |
| Admin | Organization Member 或 Organization Owner | Admin | 仓库设置、权限、高风险和紧急操作 |

GitHub 的 `Read`、`Triage`、`Write`、`Maintain` 和 `Admin` 是仓库权限；Contributor、Member、Reviewer、Maintainer 和 Admin 是 FNCache 项目角色。两者通过上表映射，但不应混为同一概念。

Organization Owner 是组织基础设施管理身份，不属于贡献者晋升链。Organization Owner 负责组织成员、仓库和安全设置，不因该身份自动获得项目 Maintainer 的技术责任。

## 4. Contributor

### 4.1 定义

Contributor 是所有参与 FNCache 公开协作、但尚未获得组织成员身份的贡献者。它是默认状态，不需要项目管理员手动授予。

### 4.2 参与方式

Contributor 可以：

- Fork 公开仓库；
- 报告 Issue；
- 参与 Discussion；
- 提交 Pull Request；
- 提交测试、文档、问题分析或设计建议。

Contributor 不拥有组织成员权限，也不能直接向受保护分支推送代码。

## 5. Member

### 5.1 定义

Member 是被邀请并接受加入 `FNCache-project` 的组织成员。Member 身份表示项目对其持续协作和社区参与建立了基础信任。

### 5.2 晋升条件

通常需要同时满足：

- 持续参与项目至少 3 个月；
- 完成至少 5 个实质性贡献，或完成 1–2 个具有明显范围和影响的大型贡献；
- 参与过 Issue 分析、测试、文档或 Pull Request 评审等协作活动；
- 获得两名现有 Member 的认可。

“实质性贡献”包括有效代码、Bug 修复、测试、故障复现、设计分析、文档、发布材料和高质量审查，不以机械性提交数量作为唯一依据。

### 5.3 权限

Member 在被授予具体仓库权限后，通常对应 GitHub `Triage`：

- 管理 Issue 和 Pull Request 的标签与分配；
- 请求 Reviewer 进行评审；
- 协助整理和关闭已解决的问题；
- 参与项目协作管理。

Member 不能直接推送代码、批准合并或修改仓库管理设置。

## 6. Reviewer

### 6.1 定义

Reviewer 是对指定仓库和模块负责的审查者。Reviewer 不是默认拥有整个仓库审批权的全局角色。

### 6.2 晋升条件

- 由两名现有 Maintainer 许可；
- 明确记录负责的仓库和模块范围；
- 能够理解并审查该模块的实现、测试和设计约束。

### 6.3 权限与责任

Reviewer 在目标仓库通常对应 GitHub `Write`：

- 审查指定模块的 Pull Request；
- 批准或要求修改符合范围的 Pull Request；
- 推送非保护分支用于修复或协作；
- 参与模块设计和测试质量维护。

Reviewer 不得批准自己的 Pull Request，也不得借助模块权限修改无关区域。跨模块变更需要相关模块 Reviewer 或 Maintainer 共同审查。

Reviewer 的批准只有在仓库分支保护规则要求相应审查时，才会成为合并门槛。

## 7. Maintainer

### 7.1 定义

Maintainer 负责一个或多个仓库的日常技术维护和质量收敛。

### 7.2 晋升条件

- 由现有 Maintainer 提名；
- 经过现有 Maintainer 的惰性共识；
- 能够持续承担代码审查、问题处理、测试和发布协作责任。

### 7.3 权限与责任

Maintainer 在目标仓库通常对应 GitHub `Maintain`：

- 维护仓库协作流程；
- 合并满足审查和测试要求的 Pull Request；
- 协调跨模块变更；
- 参与角色授予、权限调整和发布准备；
- 维护仓库的技术质量和文档一致性。

`Maintain` 不等于仓库 `Admin`。高风险仓库设置、权限管理、Webhook、Deploy Key、仓库删除和转移等操作仍属于 Admin 范围。

## 8. Admin

### 8.1 定义

Admin 是仓库级高风险管理权限，用于处理安全、权限、配置和紧急运维问题。

Admin 不是普通贡献者晋升的必经等级，也不自动代表其拥有项目技术方向的最终决定权。

### 8.2 使用范围

Admin 可以执行：

- 仓库权限和设置管理；
- 分支保护和规则维护；
- Webhook、Deploy Key 和集成管理；
- 仓库转移、归档或删除等高风险操作；
- 安全事件和紧急恢复。

Admin 权限应授予少数可信人员，并保留操作审计记录。日常代码合并优先使用 Maintainer 权限完成。

## 9. 仓库范围与生态项目

角色权限按仓库单独授予。一个人在不同仓库中可以拥有不同角色：

- 在核心仓库中担任 Maintainer；
- 在生态仓库中担任 Reviewer；
- 在实验仓库中仍为 Contributor。

加入 `FNCache-project` 不会自动获得所有未来仓库的 Triage、Write、Maintain 或 Admin 权限。

Reviewer 的权限还应绑定到实际模块，例如数据面、控制面或平台测试；在没有明确模块责任前，不授予全仓库 Reviewer 权限。

## 10. 晋升、降级与撤销

### 10.1 Sponsor

- Sponsor 必须来自目标角色的同级或更高等级；
- Sponsor 不得为申请人本人；
- 存在利益冲突时应主动回避；
- 晋升依据、Sponsor 和最终结论应保留可审计记录。

### 10.2 权限调整

以下情况可以触发降级、暂停或撤销：

- 长期不再参与项目维护；
- 主动申请退出相应角色；
- 违反安全、审查或权限边界；
- 多次绕过项目规定的测试或审查流程；
- 角色责任已转移到其他维护者。

撤销仓库权限不等于删除历史贡献记录。暂时退出维护的人员可以保留贡献记录，并在重新承担责任后重新申请相应角色。

### 10.3 初始阶段

项目初始化阶段可以由当前组织 Owner 为必要的初始维护责任直接配置仓库权限。初始化完成后，新增角色按本文规定的晋升和 Sponsor 规则执行。

## 11. 相关 GitHub 配置原则

- 组织基础身份只区分 Organization Owner 和 Organization Member；
- Contributor 不需要加入组织；
- Member、Reviewer、Maintainer 和 Admin 的仓库权限按具体仓库授予；
- 不要求当前阶段创建 Team；
- 受保护分支、CODEOWNERS 和 CI 是权限规则的技术执行手段，不改变本文角色定义；
- 任何仓库权限变化都应与本文角色记录保持一致。
