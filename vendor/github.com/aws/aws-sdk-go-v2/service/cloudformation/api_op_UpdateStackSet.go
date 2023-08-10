// Code generated by smithy-go-codegen DO NOT EDIT.

package cloudformation

import (
	"context"
	"fmt"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Updates the stack set, and associated stack instances in the specified accounts
// and Amazon Web Services Regions. Even if the stack set operation created by
// updating the stack set fails (completely or partially, below or above a
// specified failure tolerance), the stack set is updated with your changes.
// Subsequent CreateStackInstances calls on the specified stack set use the
// updated stack set.
func (c *Client) UpdateStackSet(ctx context.Context, params *UpdateStackSetInput, optFns ...func(*Options)) (*UpdateStackSetOutput, error) {
	if params == nil {
		params = &UpdateStackSetInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "UpdateStackSet", params, optFns, c.addOperationUpdateStackSetMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*UpdateStackSetOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type UpdateStackSetInput struct {

	// The name or unique ID of the stack set that you want to update.
	//
	// This member is required.
	StackSetName *string

	// [Self-managed permissions] The accounts in which to update associated stack
	// instances. If you specify accounts, you must also specify the Amazon Web
	// Services Regions in which to update stack set instances. To update all the stack
	// instances associated with this stack set, don't specify the Accounts or Regions
	// properties. If the stack set update includes changes to the template (that is,
	// if the TemplateBody or TemplateURL properties are specified), or the Parameters
	// property, CloudFormation marks all stack instances with a status of OUTDATED
	// prior to updating the stack instances in the specified accounts and Amazon Web
	// Services Regions. If the stack set update does not include changes to the
	// template or parameters, CloudFormation updates the stack instances in the
	// specified accounts and Amazon Web Services Regions, while leaving all other
	// stack instances with their existing stack instance status.
	Accounts []string

	// The Amazon Resource Name (ARN) of the IAM role to use to update this stack set.
	// Specify an IAM role only if you are using customized administrator roles to
	// control which users or groups can manage specific stack sets within the same
	// administrator account. For more information, see Granting Permissions for Stack
	// Set Operations (http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs.html)
	// in the CloudFormation User Guide. If you specified a customized administrator
	// role when you created the stack set, you must specify a customized administrator
	// role, even if it is the same customized administrator role used with this stack
	// set previously.
	AdministrationRoleARN *string

	// [Service-managed permissions] Describes whether StackSets automatically deploys
	// to Organizations accounts that are added to a target organization or
	// organizational unit (OU). If you specify AutoDeployment , don't specify
	// DeploymentTargets or Regions .
	AutoDeployment *types.AutoDeployment

	// [Service-managed permissions] Specifies whether you are acting as an account
	// administrator in the organization's management account or as a delegated
	// administrator in a member account. By default, SELF is specified. Use SELF for
	// stack sets with self-managed permissions.
	//   - If you are signed in to the management account, specify SELF .
	//   - If you are signed in to a delegated administrator account, specify
	//   DELEGATED_ADMIN . Your Amazon Web Services account must be registered as a
	//   delegated administrator in the management account. For more information, see
	//   Register a delegated administrator (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html)
	//   in the CloudFormation User Guide.
	CallAs types.CallAs

	// In some cases, you must explicitly acknowledge that your stack template
	// contains certain capabilities in order for CloudFormation to update the stack
	// set and its associated stack instances.
	//   - CAPABILITY_IAM and CAPABILITY_NAMED_IAM Some stack templates might include
	//   resources that can affect permissions in your Amazon Web Services account; for
	//   example, by creating new Identity and Access Management (IAM) users. For those
	//   stacks sets, you must explicitly acknowledge this by specifying one of these
	//   capabilities. The following IAM resources require you to specify either the
	//   CAPABILITY_IAM or CAPABILITY_NAMED_IAM capability.
	//   - If you have IAM resources, you can specify either capability.
	//   - If you have IAM resources with custom names, you must specify
	//   CAPABILITY_NAMED_IAM .
	//   - If you don't specify either of these capabilities, CloudFormation returns
	//   an InsufficientCapabilities error. If your stack template contains these
	//   resources, we recommend that you review all permissions associated with them and
	//   edit their permissions if necessary.
	//   - AWS::IAM::AccessKey (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-accesskey.html)
	//   - AWS::IAM::Group (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html)
	//   - AWS::IAM::InstanceProfile (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html)
	//   - AWS::IAM::Policy (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-policy.html)
	//   - AWS::IAM::Role (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html)
	//   - AWS::IAM::User (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-user.html)
	//   - AWS::IAM::UserToGroupAddition (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-addusertogroup.html)
	//   For more information, see Acknowledging IAM Resources in CloudFormation
	//   Templates (http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-template.html#capabilities)
	//   .
	//   - CAPABILITY_AUTO_EXPAND Some templates reference macros. If your stack set
	//   template references one or more macros, you must update the stack set directly
	//   from the processed template, without first reviewing the resulting changes in a
	//   change set. To update the stack set directly, you must acknowledge this
	//   capability. For more information, see Using CloudFormation Macros to Perform
	//   Custom Processing on Templates (http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-macros.html)
	//   . Stack sets with service-managed permissions do not currently support the use
	//   of macros in templates. (This includes the AWS::Include (http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/create-reusable-transform-function-snippets-and-add-to-your-template-with-aws-include-transform.html)
	//   and AWS::Serverless (http://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/transform-aws-serverless.html)
	//   transforms, which are macros hosted by CloudFormation.) Even if you specify this
	//   capability for a stack set with service-managed permissions, if you reference a
	//   macro in your template the stack set operation will fail.
	Capabilities []types.Capability

	// [Service-managed permissions] The Organizations accounts in which to update
	// associated stack instances. To update all the stack instances associated with
	// this stack set, do not specify DeploymentTargets or Regions . If the stack set
	// update includes changes to the template (that is, if TemplateBody or TemplateURL
	// is specified), or the Parameters , CloudFormation marks all stack instances with
	// a status of OUTDATED prior to updating the stack instances in the specified
	// accounts and Amazon Web Services Regions. If the stack set update doesn't
	// include changes to the template or parameters, CloudFormation updates the stack
	// instances in the specified accounts and Regions, while leaving all other stack
	// instances with their existing stack instance status.
	DeploymentTargets *types.DeploymentTargets

	// A brief description of updates that you are making.
	Description *string

	// The name of the IAM execution role to use to update the stack set. If you do
	// not specify an execution role, CloudFormation uses the
	// AWSCloudFormationStackSetExecutionRole role for the stack set operation. Specify
	// an IAM role only if you are using customized execution roles to control which
	// stack resources users and groups can include in their stack sets. If you specify
	// a customized execution role, CloudFormation uses that role to update the stack.
	// If you do not specify a customized execution role, CloudFormation performs the
	// update using the role previously associated with the stack set, so long as you
	// have permissions to perform operations on the stack set.
	ExecutionRoleName *string

	// Describes whether StackSets performs non-conflicting operations concurrently
	// and queues conflicting operations.
	ManagedExecution *types.ManagedExecution

	// The unique ID for this stack set operation. The operation ID also functions as
	// an idempotency token, to ensure that CloudFormation performs the stack set
	// operation only once, even if you retry the request multiple times. You might
	// retry stack set operation requests to ensure that CloudFormation successfully
	// received them. If you don't specify an operation ID, CloudFormation generates
	// one automatically. Repeating this stack set operation with a new operation ID
	// retries all stack instances whose status is OUTDATED .
	OperationId *string

	// Preferences for how CloudFormation performs this stack set operation.
	OperationPreferences *types.StackSetOperationPreferences

	// A list of input parameters for the stack set template.
	Parameters []types.Parameter

	// Describes how the IAM roles required for stack set operations are created. You
	// cannot modify PermissionModel if there are stack instances associated with your
	// stack set.
	//   - With self-managed permissions, you must create the administrator and
	//   execution roles required to deploy to target accounts. For more information, see
	//   Grant Self-Managed Stack Set Permissions (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html)
	//   .
	//   - With service-managed permissions, StackSets automatically creates the IAM
	//   roles required to deploy to accounts managed by Organizations. For more
	//   information, see Grant Service-Managed Stack Set Permissions (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-service-managed.html)
	//   .
	PermissionModel types.PermissionModels

	// The Amazon Web Services Regions in which to update associated stack instances.
	// If you specify Regions, you must also specify accounts in which to update stack
	// set instances. To update all the stack instances associated with this stack set,
	// do not specify the Accounts or Regions properties. If the stack set update
	// includes changes to the template (that is, if the TemplateBody or TemplateURL
	// properties are specified), or the Parameters property, CloudFormation marks all
	// stack instances with a status of OUTDATED prior to updating the stack instances
	// in the specified accounts and Regions. If the stack set update does not include
	// changes to the template or parameters, CloudFormation updates the stack
	// instances in the specified accounts and Regions, while leaving all other stack
	// instances with their existing stack instance status.
	Regions []string

	// The key-value pairs to associate with this stack set and the stacks created
	// from it. CloudFormation also propagates these tags to supported resources that
	// are created in the stacks. You can specify a maximum number of 50 tags. If you
	// specify tags for this parameter, those tags replace any list of tags that are
	// currently associated with this stack set. This means:
	//   - If you don't specify this parameter, CloudFormation doesn't modify the
	//   stack's tags.
	//   - If you specify any tags using this parameter, you must specify all the tags
	//   that you want associated with this stack set, even tags you've specified before
	//   (for example, when creating the stack set or during a previous update of the
	//   stack set.). Any tags that you don't include in the updated list of tags are
	//   removed from the stack set, and therefore from the stacks and resources as well.
	//
	//   - If you specify an empty value, CloudFormation removes all currently
	//   associated tags.
	// If you specify new tags as part of an UpdateStackSet action, CloudFormation
	// checks to see if you have the required IAM permission to tag resources. If you
	// omit tags that are currently associated with the stack set from the list of tags
	// you specify, CloudFormation assumes that you want to remove those tags from the
	// stack set, and checks to see if you have permission to untag resources. If you
	// don't have the necessary permission(s), the entire UpdateStackSet action fails
	// with an access denied error, and the stack set is not updated.
	Tags []types.Tag

	// The structure that contains the template body, with a minimum length of 1 byte
	// and a maximum length of 51,200 bytes. For more information, see Template Anatomy (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html)
	// in the CloudFormation User Guide. Conditional: You must specify only one of the
	// following parameters: TemplateBody or TemplateURL —or set UsePreviousTemplate
	// to true.
	TemplateBody *string

	// The location of the file that contains the template body. The URL must point to
	// a template (maximum size: 460,800 bytes) that is located in an Amazon S3 bucket
	// or a Systems Manager document. For more information, see Template Anatomy (https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html)
	// in the CloudFormation User Guide. Conditional: You must specify only one of the
	// following parameters: TemplateBody or TemplateURL —or set UsePreviousTemplate
	// to true.
	TemplateURL *string

	// Use the existing template that's associated with the stack set that you're
	// updating. Conditional: You must specify only one of the following parameters:
	// TemplateBody or TemplateURL —or set UsePreviousTemplate to true.
	UsePreviousTemplate *bool

	noSmithyDocumentSerde
}

type UpdateStackSetOutput struct {

	// The unique ID for this stack set operation.
	OperationId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationUpdateStackSetMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsAwsquery_serializeOpUpdateStackSet{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsAwsquery_deserializeOpUpdateStackSet{}, middleware.After)
	if err != nil {
		return err
	}
	if err = addSetLoggerMiddleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddClientRequestIDMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddComputeContentLengthMiddleware(stack); err != nil {
		return err
	}
	if err = addResolveEndpointMiddleware(stack, options); err != nil {
		return err
	}
	if err = v4.AddComputePayloadSHA256Middleware(stack); err != nil {
		return err
	}
	if err = addRetryMiddlewares(stack, options); err != nil {
		return err
	}
	if err = addHTTPSignerV4Middleware(stack, options); err != nil {
		return err
	}
	if err = awsmiddleware.AddRawResponseToMetadata(stack); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecordResponseTiming(stack); err != nil {
		return err
	}
	if err = addClientUserAgent(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addIdempotencyToken_opUpdateStackSetMiddleware(stack, options); err != nil {
		return err
	}
	if err = addOpUpdateStackSetValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opUpdateStackSet(options.Region), middleware.Before); err != nil {
		return err
	}
	if err = awsmiddleware.AddRecursionDetection(stack); err != nil {
		return err
	}
	if err = addRequestIDRetrieverMiddleware(stack); err != nil {
		return err
	}
	if err = addResponseErrorMiddleware(stack); err != nil {
		return err
	}
	if err = addRequestResponseLogging(stack, options); err != nil {
		return err
	}
	return nil
}

type idempotencyToken_initializeOpUpdateStackSet struct {
	tokenProvider IdempotencyTokenProvider
}

func (*idempotencyToken_initializeOpUpdateStackSet) ID() string {
	return "OperationIdempotencyTokenAutoFill"
}

func (m *idempotencyToken_initializeOpUpdateStackSet) HandleInitialize(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (
	out middleware.InitializeOutput, metadata middleware.Metadata, err error,
) {
	if m.tokenProvider == nil {
		return next.HandleInitialize(ctx, in)
	}

	input, ok := in.Parameters.(*UpdateStackSetInput)
	if !ok {
		return out, metadata, fmt.Errorf("expected middleware input to be of type *UpdateStackSetInput ")
	}

	if input.OperationId == nil {
		t, err := m.tokenProvider.GetIdempotencyToken()
		if err != nil {
			return out, metadata, err
		}
		input.OperationId = &t
	}
	return next.HandleInitialize(ctx, in)
}
func addIdempotencyToken_opUpdateStackSetMiddleware(stack *middleware.Stack, cfg Options) error {
	return stack.Initialize.Add(&idempotencyToken_initializeOpUpdateStackSet{tokenProvider: cfg.IdempotencyTokenProvider}, middleware.Before)
}

func newServiceMetadataMiddleware_opUpdateStackSet(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "cloudformation",
		OperationName: "UpdateStackSet",
	}
}
