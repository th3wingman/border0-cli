// Code generated by smithy-go-codegen DO NOT EDIT.

package ec2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

// Creates a listing for Amazon EC2 Standard Reserved Instances to be sold in the
// Reserved Instance Marketplace. You can submit one Standard Reserved Instance
// listing at a time. To get a list of your Standard Reserved Instances, you can
// use the DescribeReservedInstances operation. Only Standard Reserved Instances
// can be sold in the Reserved Instance Marketplace. Convertible Reserved Instances
// cannot be sold. The Reserved Instance Marketplace matches sellers who want to
// resell Standard Reserved Instance capacity that they no longer need with buyers
// who want to purchase additional capacity. Reserved Instances bought and sold
// through the Reserved Instance Marketplace work like any other Reserved
// Instances. To sell your Standard Reserved Instances, you must first register as
// a seller in the Reserved Instance Marketplace. After completing the registration
// process, you can create a Reserved Instance Marketplace listing of some or all
// of your Standard Reserved Instances, and specify the upfront price to receive
// for them. Your Standard Reserved Instance listings then become available for
// purchase. To view the details of your Standard Reserved Instance listing, you
// can use the DescribeReservedInstancesListings operation. For more information,
// see Reserved Instance Marketplace (https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ri-market-general.html)
// in the Amazon EC2 User Guide.
func (c *Client) CreateReservedInstancesListing(ctx context.Context, params *CreateReservedInstancesListingInput, optFns ...func(*Options)) (*CreateReservedInstancesListingOutput, error) {
	if params == nil {
		params = &CreateReservedInstancesListingInput{}
	}

	result, metadata, err := c.invokeOperation(ctx, "CreateReservedInstancesListing", params, optFns, c.addOperationCreateReservedInstancesListingMiddlewares)
	if err != nil {
		return nil, err
	}

	out := result.(*CreateReservedInstancesListingOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Contains the parameters for CreateReservedInstancesListing.
type CreateReservedInstancesListingInput struct {

	// Unique, case-sensitive identifier you provide to ensure idempotency of your
	// listings. This helps avoid duplicate listings. For more information, see
	// Ensuring Idempotency (https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Run_Instance_Idempotency.html)
	// .
	//
	// This member is required.
	ClientToken *string

	// The number of instances that are a part of a Reserved Instance account to be
	// listed in the Reserved Instance Marketplace. This number should be less than or
	// equal to the instance count associated with the Reserved Instance ID specified
	// in this call.
	//
	// This member is required.
	InstanceCount *int32

	// A list specifying the price of the Standard Reserved Instance for each month
	// remaining in the Reserved Instance term.
	//
	// This member is required.
	PriceSchedules []types.PriceScheduleSpecification

	// The ID of the active Standard Reserved Instance.
	//
	// This member is required.
	ReservedInstancesId *string

	noSmithyDocumentSerde
}

// Contains the output of CreateReservedInstancesListing.
type CreateReservedInstancesListingOutput struct {

	// Information about the Standard Reserved Instance listing.
	ReservedInstancesListings []types.ReservedInstancesListing

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata

	noSmithyDocumentSerde
}

func (c *Client) addOperationCreateReservedInstancesListingMiddlewares(stack *middleware.Stack, options Options) (err error) {
	err = stack.Serialize.Add(&awsEc2query_serializeOpCreateReservedInstancesListing{}, middleware.After)
	if err != nil {
		return err
	}
	err = stack.Deserialize.Add(&awsEc2query_deserializeOpCreateReservedInstancesListing{}, middleware.After)
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
	if err = addClientUserAgent(stack, options); err != nil {
		return err
	}
	if err = smithyhttp.AddErrorCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = smithyhttp.AddCloseResponseBodyMiddleware(stack); err != nil {
		return err
	}
	if err = addOpCreateReservedInstancesListingValidationMiddleware(stack); err != nil {
		return err
	}
	if err = stack.Initialize.Add(newServiceMetadataMiddleware_opCreateReservedInstancesListing(options.Region), middleware.Before); err != nil {
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

func newServiceMetadataMiddleware_opCreateReservedInstancesListing(region string) *awsmiddleware.RegisterServiceMetadata {
	return &awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "ec2",
		OperationName: "CreateReservedInstancesListing",
	}
}
